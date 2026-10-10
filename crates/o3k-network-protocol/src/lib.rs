//! Versioned transport types for the bounded node-local network executor.
//!
//! Canonical network intent deliberately does not depend on this crate. This
//! crate owns only the generated wire protocol and transport adapters shared
//! by the control-plane composition root and the `o3k-network` process.

pub mod proto {
    tonic::include_proto!("o3k.network.v1");
}

use proto::{
    CommandResult, ControlRequest, ControllerLease, NetworkCommand, ObserveCommand, Register,
    control_request::Body as RequestBody, control_response::Body as ResponseBody,
    network_agent_client::NetworkAgentClient as NetworkAgentGrpcClient,
};
use std::{fs, path::Path};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::{
    Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

#[derive(Debug, Error)]
pub enum NetworkTransportError {
    #[error("network transport configuration is invalid: {0}")]
    Configuration(String),
    #[error("network transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("network transport failed: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("network protocol stream failed: {0}")]
    Protocol(String),
}

#[derive(Clone)]
pub struct NetworkAgentClient {
    channel: Channel,
}

impl NetworkAgentClient {
    pub async fn connect(
        endpoint: &str,
        server_name: &str,
        ca_certificate: impl AsRef<Path>,
        client_certificate: impl AsRef<Path>,
        client_key: impl AsRef<Path>,
    ) -> Result<Self, NetworkTransportError> {
        if !endpoint.starts_with("https://") || server_name.trim().is_empty() {
            return Err(NetworkTransportError::Configuration(
                "endpoint must use https and server_name must be set".to_owned(),
            ));
        }
        let ca = fs::read(ca_certificate)?;
        let cert = fs::read(client_certificate)?;
        let key = fs::read(client_key)?;
        let tls = ClientTlsConfig::new()
            .domain_name(server_name)
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, key));
        let channel = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|error| NetworkTransportError::Configuration(error.to_string()))?
            .tls_config(tls)?
            .connect()
            .await?;
        Ok(Self { channel })
    }

    pub async fn execute(
        &self,
        register: Register,
        command: NetworkCommand,
    ) -> Result<CommandResult, NetworkTransportError> {
        self.execute_with_lease(register, command, None).await
    }

    pub async fn execute_with_lease(
        &self,
        register: Register,
        command: NetworkCommand,
        lease: Option<ControllerLease>,
    ) -> Result<CommandResult, NetworkTransportError> {
        let (tx, rx) = mpsc::channel(3);
        let mut client = NetworkAgentGrpcClient::new(self.channel.clone());
        let response = client
            .control(Request::new(ReceiverStream::new(rx)))
            .await
            .map_err(|error| NetworkTransportError::Protocol(error.to_string()))?;
        tx.send(ControlRequest {
            body: Some(RequestBody::Register(register)),
        })
        .await
        .map_err(|_| NetworkTransportError::Protocol("agent stream closed".to_owned()))?;
        if let Some(lease) = lease {
            tx.send(ControlRequest {
                body: Some(RequestBody::Lease(lease)),
            })
            .await
            .map_err(|_| NetworkTransportError::Protocol("agent stream closed".to_owned()))?;
        }
        tx.send(ControlRequest {
            body: Some(RequestBody::Command(command)),
        })
        .await
        .map_err(|_| NetworkTransportError::Protocol("agent stream closed".to_owned()))?;
        drop(tx);
        Self::collect_result(response.into_inner()).await
    }

    pub async fn observe_with_lease(
        &self,
        register: Register,
        lease: ControllerLease,
        command_id: String,
    ) -> Result<CommandResult, NetworkTransportError> {
        let (tx, rx) = mpsc::channel(3);
        let mut client = NetworkAgentGrpcClient::new(self.channel.clone());
        let response = client
            .control(Request::new(ReceiverStream::new(rx)))
            .await
            .map_err(|error| NetworkTransportError::Protocol(error.to_string()))?;
        for body in [
            RequestBody::Register(register),
            RequestBody::Lease(lease),
            RequestBody::Observe(ObserveCommand { command_id }),
        ] {
            tx.send(ControlRequest { body: Some(body) })
                .await
                .map_err(|_| NetworkTransportError::Protocol("agent stream closed".to_owned()))?;
        }
        drop(tx);
        Self::collect_result(response.into_inner()).await
    }

    async fn collect_result(
        mut stream: tonic::Streaming<proto::ControlResponse>,
    ) -> Result<CommandResult, NetworkTransportError> {
        let mut registered = false;
        while let Some(response) = stream.next().await {
            let response =
                response.map_err(|error| NetworkTransportError::Protocol(error.to_string()))?;
            match response.body {
                Some(ResponseBody::Register(_)) => registered = true,
                Some(ResponseBody::Result(result)) if registered => return Ok(result),
                Some(ResponseBody::Error(error)) => {
                    return Err(NetworkTransportError::Protocol(error.code));
                }
                Some(ResponseBody::Lease(_)) => {}
                Some(ResponseBody::Result(_)) => {
                    return Err(NetworkTransportError::Protocol(
                        "agent returned command result before registration".to_owned(),
                    ));
                }
                None => return Err(NetworkTransportError::Protocol("empty response".to_owned())),
            }
        }
        Err(NetworkTransportError::Protocol(
            "agent closed stream before command result".to_owned(),
        ))
    }
}
