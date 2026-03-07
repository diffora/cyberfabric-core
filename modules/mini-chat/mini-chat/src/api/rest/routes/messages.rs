use axum::Router;
use modkit::api::OpenApiRegistry;
use modkit::api::ensure_schema;
use modkit::api::operation_builder::OperationBuilder;

use super::AiChatLicense;
use crate::api::rest::{dto, handlers};

pub(super) fn register_message_routes(
    mut router: Router,
    openapi: &dyn OpenApiRegistry,
    prefix: &str,
) -> Router {
    // TODO(modkit): `ensure_schema` should resolve dangling `$ref` targets
    //  automatically. utoipa's derived `Page<T>::schemas()` omits `T` from
    //  its dependency list, so `Page<MessageDto>` creates a `$ref` to
    //  `MessageDto` without registering it.  Remove this workaround once
    //  `ensure_schema_raw` learns to walk `$ref` pointers and pull missing
    //  schemas into the registry.
    ensure_schema::<dto::MessageDto>(openapi);

    // GET {prefix}/v1/chats/{id}/messages
    router = OperationBuilder::get(format!("{prefix}/v1/chats/{{id}}/messages"))
        .operation_id("mini_chat.list_messages")
        .summary("List messages in a chat")
        .tag("messages")
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("id", "Chat UUID")
        .query_param_typed(
            "limit",
            false,
            "Maximum number of messages to return",
            "integer",
        )
        .query_param("cursor", false, "Cursor for pagination")
        .handler(handlers::messages::list_messages)
        .json_response_with_schema::<modkit_odata::Page<dto::MessageDto>>(
            openapi,
            http::StatusCode::OK,
            "Paginated list of messages",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // TODO: DESIGN.md specifies Google-style custom method `messages:stream`, but Axum's
    // matchit router doesn't support mixed param+literal segments. Consider adding a
    // rewrite middleware in api-gateway to map `:verb` → `/verb` so clients can use the
    // colon syntax externally while Axum routes via `/stream` internally.
    // POST {prefix}/v1/chats/{id}/messages/stream
    router = OperationBuilder::post(format!("{prefix}/v1/chats/{{id}}/messages/stream"))
        .operation_id("mini_chat.stream_message")
        .summary("Send a message and stream the response via SSE")
        .tag("messages")
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("id", "Chat UUID")
        .json_request::<dto::StreamMessageRequest>(openapi, "Message to send")
        .handler(handlers::messages::stream_message)
        .sse_json::<crate::domain::stream_events::StreamEvent>(
            openapi,
            "SSE stream of chat response events",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    router
}
