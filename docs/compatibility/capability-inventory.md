# TestLab capability inventory

This file is generated from `capability-inventory-source.json`; edit the source and rerun the generator.

- Profile: `testlab-alpha`
- Go O3K reference: `53fd2cb36ee79f42da49c8181d6ceed12b41b3aa`
- Rust reference: `3e508ea72e55a4c1e0113fbcf3643f4ffdbda735`
- Operations: `43`

Evidence states are independent: route implementation does not imply contract, CLI, or protected-runner verification.

| Service | Operation | Method | Canonical path | Implementation | Contract | CLI | Protected runner | Relevance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| compute | flavor_list | GET | /v2.1/{project_id}/flavors | implemented | verified | pending | failed | required |
| compute | flavor_create | POST | /v2.1/{project_id}/flavors | implemented | verified | pending | pending | required |
| compute | flavor_list_detail | GET | /v2.1/{project_id}/flavors/detail | implemented | verified | pending | pending | required |
| compute | flavor_delete | DELETE | /v2.1/{project_id}/flavors/{id} | implemented | verified | pending | pending | required |
| compute | flavor_show | GET | /v2.1/{project_id}/flavors/{id} | implemented | verified | pending | pending | required |
| compute | keypair_list | GET | /v2.1/{project_id}/os-keypairs | implemented | verified | verified | pending | required |
| compute | keypair_import | POST | /v2.1/{project_id}/os-keypairs | implemented | verified | verified | pending | required |
| compute | keypair_delete | DELETE | /v2.1/{project_id}/os-keypairs/{name} | implemented | verified | verified | pending | required |
| compute | keypair_show | GET | /v2.1/{project_id}/os-keypairs/{name} | implemented | verified | verified | pending | required |
| compute | server_list | GET | /v2.1/{project_id}/servers | implemented | verified | pending | pending | required |
| compute | server_create | POST | /v2.1/{project_id}/servers | implemented | verified | pending | pending | required |
| compute | server_list_detail | GET | /v2.1/{project_id}/servers/detail | implemented | verified | pending | pending | required |
| compute | server_delete | DELETE | /v2.1/{project_id}/servers/{id} | implemented | verified | pending | pending | required |
| compute | server_show | GET | /v2.1/{project_id}/servers/{id} | implemented | verified | pending | pending | required |
| compute | server_actions_start_stop_reboot_console | POST | /v2.1/{project_id}/servers/{id}/action | implemented | verified | pending | pending | required |
| identity | version_discovery_root | GET | / | implemented | verified | pending | pending | required |
| identity | version_discovery_v3 | GET | /v3 | implemented | verified | pending | pending | required |
| identity | auth_projects_list | GET | /v3/auth/projects | implemented | verified | pending | pending | required |
| identity | password_authentication_token | POST | /v3/auth/tokens | implemented | verified | verified | pending | required |
| identity | projects_list | GET | /v3/projects | implemented | verified | pending | pending | required |
| image | image_list | GET | /v2/images | implemented | verified | pending | pending | required |
| image | image_create | POST | /v2/images | implemented | verified | verified | pending | required |
| image | image_delete | DELETE | /v2/images/{id} | implemented | verified | pending | pending | required |
| image | image_show | GET | /v2/images/{id} | implemented | verified | pending | pending | required |
| image | image_download_binary | GET | /v2/images/{id}/file | implemented | verified | pending | pending | required |
| image | image_upload_binary | PUT | /v2/images/{id}/file | implemented | verified | verified | pending | required |
| network | network_list | GET | /v2.0/networks | implemented | verified | pending | pending | required |
| network | network_create | POST | /v2.0/networks | implemented | verified | pending | pending | required |
| network | network_delete | DELETE | /v2.0/networks/{id} | implemented | verified | pending | pending | required |
| network | network_show | GET | /v2.0/networks/{id} | implemented | verified | pending | pending | required |
| network | port_list | GET | /v2.0/ports | implemented | verified | pending | pending | required |
| network | port_create | POST | /v2.0/ports | implemented | verified | pending | pending | required |
| network | port_delete | DELETE | /v2.0/ports/{id} | implemented | verified | pending | pending | required |
| network | port_show | GET | /v2.0/ports/{id} | implemented | verified | pending | pending | required |
| network | subnet_list | GET | /v2.0/subnets | implemented | verified | pending | pending | required |
| network | subnet_create | POST | /v2.0/subnets | implemented | verified | pending | pending | required |
| network | subnet_delete | DELETE | /v2.0/subnets/{id} | implemented | verified | pending | pending | required |
| network | subnet_show | GET | /v2.0/subnets/{id} | implemented | verified | pending | pending | required |
| placement | allocation_candidates_list | GET | /allocation_candidates | missing | pending | pending | pending | supporting |
| placement | consumer_allocations_set | PUT | /allocations/{consumer_uuid} | missing | pending | pending | pending | supporting |
| placement | resource_provider_list | GET | /resource_providers | partial | pending | pending | pending | supporting |
| placement | resource_provider_show | GET | /resource_providers/{uuid} | partial | pending | pending | pending | supporting |
| placement | resource_provider_inventory_list | GET | /resource_providers/{uuid}/inventories | partial | pending | pending | pending | supporting |

## Known gaps

- `compute.flavor_collection_list`: Protected run 30717871057 historically observed GET /v2.1/bootstrap-project/flavors returning 405; protected evidence remains failed and requires a rerun.
- `compute.flavor_collection_create`: Protected deployment verification remains a release-gate task.
- `compute.flavor_member_delete`: Protected deployment verification remains a release-gate task.
- `compute.keypair_collection_list`: Private-key generation is intentionally unsupported.
- `compute.keypair_collection_import`: The private key never crosses the API boundary.
- `compute.keypair_member_delete`: Deletion is rejected while an owned server still references the keypair.
- `compute.server_collection_list`: The broader Nova query/filter surface and `sort_key`/`sort_dir` are deferred; bounded `limit`/`marker` paging with `servers_links` is implemented for the accepted profile.
- `compute.server_collection_create`: Real Placement and compute-agent dispatch remain pending.
- `compute.server_member_delete`: Real provider resource cleanup is tracked by later infrastructure issues.
- `compute.server_member_actions`: Console output is bounded API data; real guest serial output is tracked by #84.
- `identity.version_root`: Protected deployment verification remains a release-gate task.
- `identity.version_v3`: Protected deployment verification remains a release-gate task.
- `identity.auth_projects_list`: Client project discovery only: it returns the caller's durable role-assignment projects and exposes no pagination, links, or project writes.
- `identity.token_password_scoped`: Federation and non-password authentication are outside the alpha profile.
- `identity.token_password_scoped`: The route is the single canonical operation for both project-scoped and unscoped password authentication; an unscoped token carries no project, roles, or catalog and authorizes no O3K operation.
- `identity.projects_list`: Bounded Horizon/Instances-panel project-visibility read for the accepted compatibility profile: it returns only the caller's durable role-assignment projects and adds no project create/update/delete, no admin list-all, and no pagination/links.
- `image.collection_list`: The broad Glance filter and pagination surface is outside the alpha profile.
- `image.collection_create`: Local filesystem storage is the only alpha backend.
- `image.member_download`: Protected deployment verification remains a release-gate task.
- `image.member_upload`: Import, multi-store, and signature workflows are outside the alpha profile.
- `network.network_collection_list`: Filtering beyond the single `id` selector is out of scope, and `sort_key`/`sort_dir` are unimplemented deviations; bounded `limit`/`marker` paging with `networks_links` is implemented for the accepted profile.
- `network.network_collection_create`: Only the flat provider-network profile is in scope.
- `network.network_member_delete`: Routers, floating IPs, security groups, VXLAN, and DVR are out of scope.
- `network.port_collection_create`: One deterministic fixed IPv4 allocation is targeted initially.
- `network.port_member_delete`: Host TAP/bridge attachment is a later real-network slice.
- `network.subnet_collection_create`: One flat subnet/allocation profile is targeted initially.
- `network.subnet_member_delete`: Advanced Neutron resources remain outside the TestLab profile.
- `placement.allocation_candidates_list`: Allocation candidates and generation-aware scheduling are tracked by #82.
- `placement.allocation_member_set`: Durable local allocation state is not a public Placement allocation API.
- `placement.provider_collection_list`: Rust currently has a local durable ledger, not an HTTP Placement service.
- `placement.provider_member_show`: Provider generations and HTTP error semantics are not exposed yet.
- `placement.inventory_member_show`: Capability projection exists locally; the public Placement inventory route is missing.
