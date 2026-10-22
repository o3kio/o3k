use super::*;
use std::time::Duration;

struct SocketPath(std::path::PathBuf);
impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn blocked_command() -> Result<
    (
        SystemLvmCommandRunner,
        tokio::task::JoinHandle<Result<LvmCommandOutput, LvmCommandError>>,
        tokio::net::UnixStream,
        SocketPath,
    ),
    Box<dyn std::error::Error>,
> {
    let path =
        SocketPath(std::env::temp_dir().join(format!("o3k-lvm-drain-{}", uuid::Uuid::now_v7())));
    let listener = tokio::net::UnixListener::bind(&path.0)?;
    let runner = SystemLvmCommandRunner::default();
    let caller_runner = runner.clone();
    let args = vec!["-c".to_owned(), "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.recv(1); print('completed')".to_owned(), path.0.to_string_lossy().into_owned()];
    let caller = tokio::spawn(async move { caller_runner.run("python3", &args).await });
    let (stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await??;
    Ok((runner, caller, stream, path))
}

#[tokio::test]
async fn cancelled_lvm_caller_keeps_subprocess_owned_until_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let (runner, caller, stream, _path) = blocked_command().await?;
    caller.abort();
    assert!(caller.await.is_err());
    let mut drain = Box::pin(runner.drain(Duration::from_secs(3)));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(drain.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    stream.writable().await?;
    assert_eq!(stream.try_write(&[1])?, 1);
    drain.await?;
    assert!(
        runner
            .owned
            .tasks
            .lock()
            .map_err(|_| std::io::Error::other("command registry poisoned"))?
            .is_empty()
    );
    assert!(
        runner
            .run(
                "python3",
                &["-c".into(), "raise RuntimeError('must not start')".into()]
            )
            .await
            .is_err()
    );
    runner.drain(Duration::from_secs(1)).await?;
    Ok(())
}

#[tokio::test]
async fn lvm_command_deadline_cannot_be_retried_as_success()
-> Result<(), Box<dyn std::error::Error>> {
    let (runner, caller, stream, _path) = blocked_command().await?;
    assert!(runner.drain(Duration::ZERO).await.is_err());
    assert!(runner.run("python3", &[]).await.is_err());
    stream.writable().await?;
    assert_eq!(stream.try_write(&[1])?, 1);
    let output = tokio::time::timeout(Duration::from_secs(3), caller).await???;
    assert_eq!(output.stdout.trim(), "completed");
    assert!(runner.drain(Duration::from_secs(1)).await.is_err());
    Ok(())
}
