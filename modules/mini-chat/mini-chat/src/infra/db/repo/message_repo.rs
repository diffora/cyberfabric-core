use std::collections::HashMap;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use modkit_db::odata::{LimitCfg, paginate_odata};
use modkit_db::secure::{DBRunner, SecureEntityExt, exec_custom_all, secure_insert};
use modkit_odata::{ODataQuery, Page, SortDir};
use modkit_security::AccessScope;
use sea_orm::{
    ColumnTrait, Condition, EntityTrait, FromQueryResult, JoinType, Order, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, Set,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::models::{AttachmentSummary, ImgThumbnail};
use crate::domain::repos::{InsertAssistantMessageParams, InsertUserMessageParams};
use crate::infra::db::entity::attachment::Column as AttCol;
use crate::infra::db::entity::message::{
    ActiveModel, Column, Entity as MessageEntity, MessageRole, Model as MessageModel,
};
use crate::infra::db::entity::message_attachment::{
    Column as MaCol, Entity as MaEntity, Relation as MaRelation,
};
use crate::infra::db::odata_mapper::{MessageField, MessageODataMapper};

/// Flat row returned by the `message_attachments` ⟕ attachments join query.
#[derive(Debug, FromQueryResult)]
struct AttachmentRow {
    message_id: Uuid,
    attachment_id: Uuid,
    attachment_kind: String,
    filename: String,
    status: String,
    img_thumbnail: Option<Vec<u8>>,
    img_thumbnail_width: Option<i32>,
    img_thumbnail_height: Option<i32>,
}

pub struct MessageRepository {
    limit_cfg: LimitCfg,
}

impl MessageRepository {
    #[must_use]
    pub fn new(limit_cfg: LimitCfg) -> Self {
        Self { limit_cfg }
    }
}

#[async_trait]
impl crate::domain::repos::MessageRepository for MessageRepository {
    async fn insert_user_message<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: InsertUserMessageParams,
    ) -> Result<MessageModel, DomainError> {
        let now = OffsetDateTime::now_utc();
        let am = ActiveModel {
            id: Set(params.id),
            tenant_id: Set(params.tenant_id),
            chat_id: Set(params.chat_id),
            request_id: Set(Some(params.request_id)),
            role: Set(MessageRole::User),
            content: Set(params.content),
            content_type: Set("text".to_owned()),
            token_estimate: Set(0),
            provider_response_id: Set(None),
            request_kind: Set(Some("chat".to_owned())),
            features_used: Set(serde_json::json!([])),
            input_tokens: Set(0),
            output_tokens: Set(0),
            model: Set(None),
            is_compressed: Set(false),
            created_at: Set(now),
            deleted_at: Set(None),
        };
        Ok(secure_insert::<MessageEntity>(am, scope, runner).await?)
    }

    async fn insert_assistant_message<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: InsertAssistantMessageParams,
    ) -> Result<MessageModel, DomainError> {
        let now = OffsetDateTime::now_utc();
        let am = ActiveModel {
            id: Set(params.id),
            tenant_id: Set(params.tenant_id),
            chat_id: Set(params.chat_id),
            request_id: Set(Some(params.request_id)),
            role: Set(MessageRole::Assistant),
            content: Set(params.content),
            content_type: Set("text".to_owned()),
            token_estimate: Set(0),
            provider_response_id: Set(params.provider_response_id),
            request_kind: Set(Some("chat".to_owned())),
            features_used: Set(serde_json::json!([])),
            input_tokens: Set(params.input_tokens.unwrap_or(0)),
            output_tokens: Set(params.output_tokens.unwrap_or(0)),
            model: Set(params.model),
            is_compressed: Set(false),
            created_at: Set(now),
            deleted_at: Set(None),
        };
        Ok(secure_insert::<MessageEntity>(am, scope, runner).await?)
    }

    async fn find_by_chat_and_request_id<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
        request_id: Uuid,
    ) -> Result<Vec<MessageModel>, DomainError> {
        Ok(MessageEntity::find()
            .filter(
                Condition::all()
                    .add(Column::ChatId.eq(chat_id))
                    .add(Column::RequestId.eq(request_id))
                    .add(Column::DeletedAt.is_null()),
            )
            .secure()
            .scope_with(scope)
            .order_by(Column::CreatedAt, Order::Asc)
            .all(runner)
            .await?)
    }

    async fn get_by_chat<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        msg_id: Uuid,
        chat_id: Uuid,
    ) -> Result<Option<MessageModel>, DomainError> {
        Ok(MessageEntity::find()
            .filter(
                Condition::all()
                    .add(Column::Id.eq(msg_id))
                    .add(Column::ChatId.eq(chat_id))
                    .add(Column::DeletedAt.is_null()),
            )
            .secure()
            .scope_with(scope)
            .one(runner)
            .await?)
    }

    async fn list_by_chat<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
        query: &ODataQuery,
    ) -> Result<Page<MessageModel>, DomainError> {
        let base_query = MessageEntity::find()
            .filter(
                Condition::all()
                    .add(Column::ChatId.eq(chat_id))
                    .add(Column::RequestId.is_not_null())
                    .add(Column::DeletedAt.is_null()),
            )
            .secure()
            .scope_with(scope);

        let page = paginate_odata::<MessageField, MessageODataMapper, _, _, _, _>(
            base_query,
            runner,
            query,
            ("created_at", SortDir::Asc),
            self.limit_cfg,
            std::convert::identity,
        )
        .await
        .map_err(|e| DomainError::database(e.to_string()))?;

        Ok(page)
    }

    async fn batch_attachment_summaries<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
        message_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<AttachmentSummary>>, DomainError> {
        if message_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let tenant_ids =
            scope.all_uuid_values_for(modkit_security::pep_properties::OWNER_TENANT_ID);

        // Single join query: message_attachments ⟕ attachments
        // Selecting only the columns needed for AttachmentSummary.
        let select = MaEntity::find()
            .select_only()
            .column(MaCol::MessageId)
            .column_as(AttCol::Id, "attachment_id")
            .column(AttCol::AttachmentKind)
            .column(AttCol::Filename)
            .column(AttCol::Status)
            .column(AttCol::ImgThumbnail)
            .column(AttCol::ImgThumbnailWidth)
            .column(AttCol::ImgThumbnailHeight)
            .join(JoinType::InnerJoin, MaRelation::Attachment.def())
            .filter(
                Condition::all()
                    .add(MaCol::TenantId.is_in(tenant_ids))
                    .add(MaCol::ChatId.eq(chat_id))
                    .add(MaCol::MessageId.is_in(message_ids.iter().copied()))
                    .add(AttCol::DeletedAt.is_null()),
            )
            .order_by(MaCol::CreatedAt, Order::Asc)
            .order_by(AttCol::Id, Order::Asc)
            .into_model::<AttachmentRow>();

        let rows: Vec<AttachmentRow> = exec_custom_all(select, runner)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let mut map: HashMap<Uuid, Vec<AttachmentSummary>> =
            HashMap::with_capacity(message_ids.len());
        for row in rows {
            let thumbnail = match (
                row.img_thumbnail.as_ref(),
                row.img_thumbnail_width,
                row.img_thumbnail_height,
            ) {
                (Some(bytes), Some(w), Some(h)) if !bytes.is_empty() => Some(ImgThumbnail {
                    content_type: "image/webp".to_owned(),
                    width: w,
                    height: h,
                    data_base64: BASE64.encode(bytes),
                }),
                _ => None,
            };
            map.entry(row.message_id)
                .or_default()
                .push(AttachmentSummary {
                    attachment_id: row.attachment_id,
                    kind: row.attachment_kind,
                    filename: row.filename,
                    status: row.status,
                    img_thumbnail: thumbnail,
                });
        }
        Ok(map)
    }
}

#[cfg(test)]
#[path = "message_repo_test.rs"]
mod tests;
