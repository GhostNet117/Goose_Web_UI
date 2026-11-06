## methods
- _goose/unstable/session/extensions/add
    REQ AddSessionExtensionRequest_unstable { sessionId:string, extension:GooseExtension }
    RES EmptyResponse = object
- _goose/unstable/session/extensions/remove
    REQ RemoveSessionExtensionRequest_unstable { sessionId:string, extensionKey:string }
    RES EmptyResponse = object
- _goose/unstable/tools/list
    REQ GetToolsRequest_unstable { sessionId:string, extensionName?:string|null }
    RES GetToolsResponse_unstable { tools:[ToolListItem] }
- _goose/unstable/tools/permissions/set
    REQ SetToolPermissionsRequest_unstable { toolPermissions:[ToolPermissionEntry] }
    RES SetToolPermissionsResponse_unstable = object
- _goose/unstable/tools/call
    REQ GooseToolCallRequest_unstable { sessionId:string, extensionName:string, name:string, arguments?:None }
    RES GooseToolCallResponse_unstable { content?:[None], structuredContent?:None, isError:boolean, _meta?:None }
- _goose/unstable/resources/read
    REQ ReadResourceRequest_unstable { sessionId:string, uri:string, extensionName:string }
    RES ReadResourceResponse_unstable { result?:None }
- _goose/unstable/apps/list
    REQ AppsListRequest_unstable { sessionId?:string|null }
    RES AppsListResponse_unstable { apps?:[None] }
- _goose/unstable/apps/export
    REQ AppsExportRequest_unstable { name:string }
    RES AppsExportResponse_unstable { html:string }
- _goose/unstable/apps/import
    REQ AppsImportRequest_unstable { html:string }
    RES AppsImportResponse_unstable { name:string, message:string }
- _goose/unstable/apps/delete
    REQ AppsDeleteRequest_unstable { name:string }
    RES AppsDeleteResponse_unstable { name:string, message:string }
- _goose/unstable/session/working-dir/update
    REQ UpdateWorkingDirRequest_unstable { sessionId:string, workingDir:string }
    RES EmptyResponse = object
- _goose/unstable/session/system-prompt/set
    REQ SetSessionSystemPromptRequest_unstable { sessionId:string, mode?:SessionSystemPromptMode, key?:string|null, text:string }
    RES EmptyResponse = object
- _goose/unstable/session/steer
    REQ SteerSessionRequest_unstable { sessionId:string, prompt?:[ContentBlock], expectedRunId:string }
    RES SteerSessionResponse_unstable { runId:string, messageId:string }
- _goose/unstable/session/live-voice/availability
    REQ LiveVoiceAvailabilityRequest_unstable { sessionId?:string|null, _meta?:object|null }
    RES LiveVoiceAvailabilityResponse_unstable { status:LiveVoiceStatus, message:string }
- _goose/unstable/session/live-voice/start
    REQ LiveVoiceStartRequest_unstable { sessionId:string, offerSdp:string, _meta?:object|null }
    RES LiveVoiceStartResponse_unstable { interactionId:string, answerSdp:string }
- _goose/unstable/session/live-voice/stop
    REQ LiveVoiceStopRequest_unstable { sessionId:string, interactionId:string }
    RES EmptyResponse = object
- _goose/unstable/diagnostics/get
    REQ DiagnosticsGetRequest_unstable { sessionId:string, level?:DiagnosticsReportLevel }
    RES DiagnosticsGetResponse_unstable { report:None }
- _goose/unstable/config/prompts/list
    REQ ListPromptsRequest_unstable = object
    RES ListPromptsResponse_unstable { prompts:[PromptTemplateEntry] }
- _goose/unstable/config/prompts/get
    REQ GetPromptRequest_unstable { name:string }
    RES GetPromptResponse_unstable { name:string, content:string, defaultContent:string, isCustomized:boolean }
- _goose/unstable/config/prompts/save
    REQ SavePromptRequest_unstable { name:string, content:string }
    RES PromptOperationResponse_unstable { message:string }
- _goose/unstable/config/prompts/reset
    REQ ResetPromptRequest_unstable { name:string }
    RES PromptOperationResponse_unstable { message:string }
- _goose/unstable/config/extensions/list
    REQ GetConfigExtensionsRequest_unstable = object
    RES GetConfigExtensionsResponse_unstable { extensions:[GooseExtensionEntry], warnings?:[string] }
- _goose/unstable/config/extensions/add
    REQ AddConfigExtensionRequest_unstable { extension:GooseExtension, enabled?:boolean }
    RES EmptyResponse = object
- _goose/unstable/config/extensions/remove
    REQ RemoveConfigExtensionRequest_unstable { configKey:string }
    RES EmptyResponse = object
- _goose/unstable/config/extensions/set-enabled
    REQ SetConfigExtensionEnabledRequest_unstable { configKey:string, enabled:boolean }
    RES EmptyResponse = object
- _goose/unstable/session/extensions/list
    REQ GetSessionExtensionsRequest_unstable { sessionId:string }
    RES GetSessionExtensionsResponse_unstable { extensions:[SessionExtensionEntry] }
- _goose/unstable/providers/list
    REQ ListProvidersRequest_unstable { providerIds?:[string] }
    RES ListProvidersResponse_unstable { entries:[ProviderInventoryEntryDto] }
- _goose/unstable/providers/supported-models/list
    REQ ProviderSupportedModelsListRequest_unstable { providerId:string }
    RES ProviderSupportedModelsListResponse_unstable { providerId:string, models:[string] }
- _goose/unstable/providers/catalog/list
    REQ ProviderCatalogListRequest_unstable { format?:string|null }
    RES ProviderCatalogListResponse_unstable { providers:[ProviderTemplateCatalogEntryDto] }
- _goose/unstable/providers/setup/catalog/list
    REQ ProviderSetupCatalogListRequest_unstable = object
    RES ProviderSetupCatalogListResponse_unstable { providers:[ProviderSetupCatalogEntryDto] }
- _goose/unstable/providers/catalog/template
    REQ ProviderCatalogTemplateRequest_unstable { providerId:string }
    RES ProviderCatalogTemplateResponse_unstable { template:ProviderTemplateDto }
- _goose/unstable/providers/custom/create
    REQ CustomProviderCreateRequest_unstable { engine:string, displayName:string, apiUrl:string, apiKey?:string|null, models?:[string], supportsStreaming?:boolean|null, headers?:map<string>, requiresAuth:boolean, catalogProviderId?:string|null, basePath?:string|null, preservesThinking?:boolean|null, toolshim:boolean }
    RES CustomProviderCreateResponse_unstable { providerId:string, status:ProviderConfigStatusDto, refresh:RefreshProviderInventoryResponse_unstable }
- _goose/unstable/providers/custom/read
    REQ CustomProviderReadRequest_unstable { providerId:string }
    RES CustomProviderReadResponse_unstable { provider:CustomProviderConfigDto, editable:boolean, status:ProviderConfigStatusDto }
- _goose/unstable/providers/custom/update
    REQ CustomProviderUpdateRequest_unstable { providerId:string, engine:string, displayName:string, apiUrl:string, apiKey?:string|null, models?:[string], supportsStreaming?:boolean|null, headers?:map<string>, requiresAuth:boolean, catalogProviderId?:string|null, basePath?:string|null, preservesThinking?:boolean|null, toolshim:boolean }
    RES CustomProviderUpdateResponse_unstable { providerId:string, status:ProviderConfigStatusDto, refresh:RefreshProviderInventoryResponse_unstable }
- _goose/unstable/providers/custom/delete
    REQ CustomProviderDeleteRequest_unstable { providerId:string }
    RES CustomProviderDeleteResponse_unstable { providerId:string, refresh:RefreshProviderInventoryResponse_unstable }
- _goose/unstable/providers/inventory/refresh
    REQ RefreshProviderInventoryRequest_unstable { providerIds?:[string] }
    RES RefreshProviderInventoryResponse_unstable { started:[string], skipped?:[RefreshProviderInventorySkipDto] }
- _goose/unstable/providers/readiness/check
    REQ ProviderReadinessCheckRequest_unstable { providerId:string }
    RES ProviderReadinessCheckResponse_unstable { providerId:string, ready:boolean, error?:string|null }
- _goose/unstable/providers/config/read
    REQ ProviderConfigReadRequest_unstable { providerId:string }
    RES ProviderConfigReadResponse_unstable { fields:[ProviderConfigFieldValueDto] }
- _goose/unstable/providers/config/status
    REQ ProviderConfigStatusRequest_unstable { providerIds?:[string] }
    RES ProviderConfigStatusResponse_unstable { statuses:[ProviderConfigStatusDto] }
- _goose/unstable/providers/config/save
    REQ ProviderConfigSaveRequest_unstable { providerId:string, fields:[ProviderConfigFieldUpdate] }
    RES ProviderConfigChangeResponse_unstable { status:ProviderConfigStatusDto, refresh:RefreshProviderInventoryResponse_unstable }
- _goose/unstable/providers/config/delete
    REQ ProviderConfigDeleteRequest_unstable { providerId:string }
    RES ProviderConfigChangeResponse_unstable { status:ProviderConfigStatusDto, refresh:RefreshProviderInventoryResponse_unstable }
- _goose/unstable/providers/config/authenticate
    REQ ProviderConfigAuthenticateRequest_unstable { providerId:string }
    RES ProviderConfigChangeResponse_unstable { status:ProviderConfigStatusDto, refresh:RefreshProviderInventoryResponse_unstable }
- _goose/unstable/providers/secrets/list
    REQ ProviderSecretsListRequest_unstable = object
    RES ProviderSecretsListResponse_unstable { secrets:[ProviderSecretDto] }
- _goose/unstable/providers/secrets/delete
    REQ ProviderSecretDeleteRequest_unstable { id:string }
    RES EmptyResponse = object
- _goose/unstable/providers/canonical-model-info
    REQ CanonicalModelInfoRequest_unstable { provider:string, model:string }
    RES CanonicalModelInfoResponse_unstable { modelInfo?:CanonicalModelInfoDto|null }
- _goose/unstable/preferences/read
    REQ PreferencesReadRequest_unstable { keys?:[PreferenceKey] }
    RES PreferencesReadResponse_unstable { values:[PreferenceValue] }
- _goose/unstable/preferences/save
    REQ PreferencesSaveRequest_unstable { values?:[PreferenceValue] }
    RES EmptyResponse = object
- _goose/unstable/config/read
    REQ ConfigReadRequest_unstable { key:string, isSecret?:boolean }
    RES ConfigReadResponse_unstable { value?:None }
- _goose/unstable/config/upsert
    REQ ConfigUpsertRequest_unstable { key:string, value:None, isSecret?:boolean }
    RES EmptyResponse = object
- _goose/unstable/config/remove
    REQ ConfigRemoveRequest_unstable { key:string, isSecret?:boolean }
    RES EmptyResponse = object
- _goose/unstable/config/read-all
    REQ ConfigReadAllRequest_unstable = object
    RES ConfigReadAllResponse_unstable { config:map<None> }
- _goose/unstable/defaults/read
    REQ DefaultsReadRequest_unstable = object
    RES DefaultsReadResponse_unstable { providerId?:string|null, modelId?:string|null }
- _goose/unstable/defaults/save
    REQ DefaultsSaveRequest_unstable { providerId:string, modelId?:string|null }
    RES DefaultsReadResponse_unstable { providerId?:string|null, modelId?:string|null }
- _goose/unstable/defaults/clear
    REQ DefaultsClearRequest_unstable = object
    RES DefaultsReadResponse_unstable { providerId?:string|null, modelId?:string|null }
- _goose/unstable/onboarding/import/scan
    REQ OnboardingImportScanRequest_unstable { sources?:[OnboardingImportSourceKind] }
    RES OnboardingImportScanResponse_unstable { candidates:[OnboardingImportCandidate] }
- _goose/unstable/onboarding/import/apply
    REQ OnboardingImportApplyRequest_unstable { candidateIds?:[string], enableImportedExtensions?:boolean }
    RES OnboardingImportApplyResponse_unstable { imported:OnboardingImportCounts, skipped:OnboardingImportCounts, warnings?:[string], providerDefaults?:DefaultsReadResponse_unstable|null }
- _goose/unstable/session/export
    REQ ExportSessionRequest_unstable { sessionId:string, format?:SessionExportFormat }
    RES ExportSessionResponse_unstable { data:string }
- _goose/unstable/session/import
    REQ ImportSessionRequest_unstable { input:string }
    RES ImportSessionResponse_unstable { sessionId:string, title?:string|null, updatedAt?:string|null, messageCount:integer }
- _goose/unstable/recipes/encode
    REQ EncodeRecipeRequest_unstable { recipe:RecipeDto }
    RES EncodeRecipeResponse_unstable { deeplink:string }
- _goose/unstable/recipes/decode
    REQ DecodeRecipeRequest_unstable { deeplink:string }
    RES DecodeRecipeResponse_unstable { recipe:RecipeDto }
- _goose/unstable/recipes/scan
    REQ ScanRecipeRequest_unstable { recipe:RecipeDto }
    RES ScanRecipeResponse_unstable { has_security_warnings:boolean }
- _goose/unstable/recipes/list
    REQ ListRecipesRequest_unstable = object
    RES ListRecipesResponse_unstable { recipes:[RecipeListEntryDto] }
- _goose/unstable/recipes/delete
    REQ DeleteRecipeRequest_unstable { id:string }
    RES EmptyResponse = object
- _goose/unstable/recipes/schedule
    REQ ScheduleRecipeRequest_unstable { id:string, cron_schedule?:string|null }
    RES EmptyResponse = object
- _goose/unstable/recipes/slash-command
    REQ SetRecipeSlashCommandRequest_unstable { id:string, slash_command?:string|null }
    RES EmptyResponse = object
- _goose/unstable/recipes/save
    REQ SaveRecipeRequest_unstable { recipe:RecipeDto, id?:string|null }
    RES SaveRecipeResponse_unstable { id:string, file_name:string, file_path:string }
- _goose/unstable/recipes/parse
    REQ ParseRecipeRequest_unstable { content:string }
    RES ParseRecipeResponse_unstable { recipe:RecipeDto }
- _goose/unstable/recipes/to-yaml
    REQ RecipeToYamlRequest_unstable { recipe:RecipeDto }
    RES RecipeToYamlResponse_unstable { yaml:string }
- _goose/unstable/schedules/list
    REQ ListSchedulesRequest_unstable = object
    RES ListSchedulesResponse_unstable { jobs:[ScheduledJobDto] }
- _goose/unstable/schedules/sessions/list
    REQ ListScheduleSessionsRequest_unstable { scheduleId:string, limit:integer }
    RES ListScheduleSessionsResponse_unstable { sessions:[SessionInfo] }
- _goose/unstable/schedules/create
    REQ CreateScheduleRequest_unstable { id:string, recipe:RecipeDto, cron:string }
    RES CreateScheduleResponse_unstable { job:ScheduledJobDto }
- _goose/unstable/schedules/delete
    REQ DeleteScheduleRequest_unstable { scheduleId:string }
    RES EmptyResponse = object
- _goose/unstable/schedules/pause
    REQ PauseScheduleRequest_unstable { scheduleId:string }
    RES EmptyResponse = object
- _goose/unstable/schedules/unpause
    REQ UnpauseScheduleRequest_unstable { scheduleId:string }
    RES EmptyResponse = object
- _goose/unstable/schedules/update
    REQ UpdateScheduleRequest_unstable { scheduleId:string, cron:string }
    RES UpdateScheduleResponse_unstable { job:ScheduledJobDto }
- _goose/unstable/schedules/run-now
    REQ RunScheduleNowRequest_unstable { scheduleId:string }
    RES RunScheduleNowResponse_unstable { status:RunScheduleNowStatus, sessionId?:string|null }
- _goose/unstable/schedules/running-job/kill
    REQ KillRunningJobRequest_unstable { jobId:string }
    RES KillRunningJobResponse_unstable { message:string }
- _goose/unstable/schedules/running-job/inspect
    REQ InspectRunningJobRequest_unstable { jobId:string }
    RES InspectRunningJobResponse_unstable { running:boolean, sessionId?:string|null, jobStartTime?:string|null, runningDurationSeconds?:integer|null }
- _goose/unstable/session/info
    REQ GetSessionInfoRequest_unstable { sessionId:string }
    RES GetSessionInfoResponse_unstable { session:SessionInfo }
- _goose/unstable/session/conversation/truncate
    REQ TruncateSessionConversationRequest_unstable { sessionId:string, truncateFrom:integer }
    RES EmptyResponse = object
- _goose/unstable/session/project/update
    REQ UpdateSessionProjectRequest_unstable { sessionId:string, projectId?:string|null }
    RES EmptyResponse = object
- _goose/unstable/session/rename
    REQ RenameSessionRequest_unstable { sessionId:string, title:string }
    RES EmptyResponse = object
- _goose/unstable/session/archive
    REQ ArchiveSessionRequest_unstable { sessionId:string }
    RES EmptyResponse = object
- _goose/unstable/session/unarchive
    REQ UnarchiveSessionRequest_unstable { sessionId:string }
    RES EmptyResponse = object
- _goose/unstable/sources/create
    REQ CreateSourceRequest_unstable { type:SourceType, name:string, description:string, content:string, target:SourceScope, properties?:map<None> }
    RES CreateSourceResponse_unstable { source:SourceEntry }
- _goose/unstable/sources/list
    REQ ListSourcesRequest_unstable { type?:SourceType|null, projectDir?:string|null, includeProjectSources?:boolean }
    RES ListSourcesResponse_unstable { sources:[SourceEntry] }
- _goose/unstable/agent-mentions/list
    REQ ListAgentMentionsRequest_unstable { cwd?:string|null, sessionId?:string|null }
    RES ListAgentMentionsResponse_unstable { agents:[AgentMention] }
- _goose/unstable/slash-commands/list
    REQ ListSlashCommandsRequest_unstable { cwd?:string|null, sessionId?:string|null }
    RES ListSlashCommandsResponse_unstable { availableCommands:[AvailableCommand] }
- _goose/unstable/sources/update
    REQ UpdateSourceRequest_unstable { type:SourceType, path:string, name:string, description:string, content:string, properties?:object|null }
    RES UpdateSourceResponse_unstable { source:SourceEntry }
- _goose/unstable/sources/delete
    REQ DeleteSourceRequest_unstable { type:SourceType, path:string }
    RES EmptyResponse = object
- _goose/unstable/sources/export
    REQ ExportSourceRequest_unstable { type:SourceType, path:string }
    RES ExportSourceResponse_unstable { json:string, filename:string }
- _goose/unstable/sources/import
    REQ ImportSourcesRequest_unstable { data:string, target:SourceScope }
    RES ImportSourcesResponse_unstable { sources:[SourceEntry] }
- _goose/unstable/dictation/transcribe
    REQ DictationTranscribeRequest_unstable { audio:string, mimeType:string, provider:string }
    RES DictationTranscribeResponse_unstable { text:string }
- _goose/unstable/dictation/config
    REQ DictationConfigRequest_unstable = object
    RES DictationConfigResponse_unstable { providers:map<DictationProviderStatusEntry> }
- _goose/unstable/dictation/models/list
    REQ DictationModelsListRequest_unstable = object
    RES DictationModelsListResponse_unstable { models:[DictationLocalModelStatus] }
- _goose/unstable/dictation/models/download
    REQ DictationModelDownloadRequest_unstable { modelId:string }
    RES EmptyResponse = object
- _goose/unstable/dictation/models/download/progress
    REQ DictationModelDownloadProgressRequest_unstable { modelId:string }
    RES DictationModelDownloadProgressResponse_unstable { progress?:DictationDownloadProgress|null }
- _goose/unstable/dictation/models/cancel
    REQ DictationModelCancelRequest_unstable { modelId:string }
    RES EmptyResponse = object
- _goose/unstable/dictation/models/delete
    REQ DictationModelDeleteRequest_unstable { modelId:string }
    RES EmptyResponse = object
- _goose/unstable/local-inference/models/list
    REQ LocalInferenceModelsListRequest_unstable = object
    RES LocalInferenceModelsListResponse_unstable { models:[LocalInferenceModelDto] }
- _goose/unstable/local-inference/models/download
    REQ LocalInferenceModelDownloadRequest_unstable { spec:string, backendId?:string|null, variantId?:string|null }
    RES LocalInferenceModelDownloadResponse_unstable { modelId:string }
- _goose/unstable/local-inference/models/download/progress
    REQ LocalInferenceModelDownloadProgressRequest_unstable { modelId:string }
    RES LocalInferenceModelDownloadProgressResponse_unstable { progress?:LocalInferenceDownloadProgressDto|null }
- _goose/unstable/local-inference/models/download/cancel
    REQ LocalInferenceModelDownloadCancelRequest_unstable { modelId:string }
    RES EmptyResponse = object
- _goose/unstable/local-inference/models/delete
    REQ LocalInferenceModelDeleteRequest_unstable { modelId:string }
    RES EmptyResponse = object
- _goose/unstable/local-inference/models/evict
    REQ LocalInferenceModelEvictRequest_unstable { modelId:string }
    RES EmptyResponse = object
- _goose/unstable/local-inference/models/settings/read
    REQ LocalInferenceModelSettingsReadRequest_unstable { modelId:string }
    RES LocalInferenceModelSettingsReadResponse_unstable { settings:LocalInferenceModelSettingsDto }
- _goose/unstable/local-inference/models/settings/update
    REQ LocalInferenceModelSettingsUpdateRequest_unstable { modelId:string, settings:LocalInferenceModelSettingsDto }
    RES LocalInferenceModelSettingsUpdateResponse_unstable { settings:LocalInferenceModelSettingsDto }
- _goose/unstable/local-inference/huggingface/search
    REQ LocalInferenceHuggingFaceSearchRequest_unstable { query:string, limit?:integer|null }
    RES LocalInferenceHuggingFaceSearchResponse_unstable { models:[LocalInferenceHfModelInfoDto] }
- _goose/unstable/local-inference/huggingface/repo/variants
    REQ LocalInferenceHuggingFaceRepoVariantsRequest_unstable { repoId:string }
    RES LocalInferenceHuggingFaceRepoVariantsResponse_unstable { variants:[LocalInferenceHfModelVariantDto], recommendedIndex?:integer|null, availableMemoryBytes:integer, downloadedQuants:[string], downloadedVariants:[string] }
- _goose/unstable/local-inference/chat-templates/builtin/list
    REQ LocalInferenceBuiltinChatTemplatesListRequest_unstable = object
    RES LocalInferenceBuiltinChatTemplatesListResponse_unstable { templates:[string] }
## agentRequests
- _goose/unstable/session/recipe/request-params
    REQ RequestRecipeParams_unstable { sessionId:string, parameters:[RecipeParameterDto], parameterScopeId?:string|null }
    RES RecipeParamsResponse_unstable { action?:RecipeParamsAction, values?:map<string> }
## notifications
- _goose/unstable/session/update  GooseSessionNotification_unstable { sessionId:string, update:GooseSessionUpdate }
- _goose/unstable/providers/authentication/device-code  ProviderDeviceCodeNotification_unstable { providerId:string, userCode:string, verificationUri:string, expiresIn:integer }
## referenced types
- AgentMention { name:string, description:string, sourceType:SourceType, sourcePath?:string|null, mention:string }
- Annotations { audience?:array|null, lastModified?:string|null, priority?:number|null, _meta?:object|null }
- AudioContent { annotations?:Annotations|null, data:string, mimeType:string, _meta?:object|null }
- AvailableCommand { name:string, description:string, input?:AvailableCommandInput|null, _meta?:object|null }
- AvailableCommandInput = UnstructuredCommandInput
- BlobResourceContents { blob:string, mimeType?:string|null, uri:string, _meta?:object|null }
- CanonicalModelInfoDto { provider:string, model:string, contextLimit:integer, maxOutputTokens?:integer|null, reasoning:boolean, inputTokenCost?:number|null, outputTokenCost?:number|null, cacheReadTokenCost?:number|null, cacheWriteTokenCost?:number|null, currency:string }
- ContentBlock = TextContent | ImageContent | AudioContent | ResourceLink | EmbeddedResource
- CostSourceData = const(provider_reported) | const(estimated)
- CustomProviderConfigDto { providerId:string, engine:string, displayName:string, apiUrl:string, models?:[string], supportsStreaming?:boolean|null, headers?:map<string>, requiresAuth:boolean, catalogProviderId?:string|null, basePath?:string|null, toolshim:boolean, apiKeyEnv?:string|null, apiKeySet:boolean, preservesThinking:boolean }
- DiagnosticsReportLevel = enum(summary,full)
- DictationDownloadProgress { bytesDownloaded:integer, totalBytes:integer, progressPercent:number, status:string, error?:string|null }
- DictationLocalModelStatus { id:string, label:string, description:string, sizeMb:integer, downloaded:boolean, downloadInProgress:boolean, recommended:boolean }
- DictationModelOption { id:string, label:string, description:string }
- DictationProviderStatusEntry { configured:boolean, host?:string|null, description:string, usesProviderConfig:boolean, settingsPath?:string|null, configKey?:string|null, modelConfigKey?:string|null, defaultModel?:string|null, selectedModel?:string|null, availableModels?:[DictationModelOption] }
- EmbeddedResource { annotations?:Annotations|null, resource:EmbeddedResourceResource, _meta?:object|null }
- EmbeddedResourceResource = TextResourceContents | BlobResourceContents
- EnvVariable { name:string, value:string, _meta?:object|null }
- GooseExtension = {name:string, description:string|null, display_name:string|null, timeout:integer|null, bundled:boolean|null, available_tools:array|null, type:const(builtin)} | {name:string, description:string|null, display_name:string|null, bundled:boolean|null, available_tools:array|null, type:const(platform)} | {server:McpServer, envKeys:[string], description:string|null, timeout:integer|null, socket:string|null, clientId:string|null, clientSecretKey:string|null, scopes:[string], bundled:boolean|null, available_tools:array|null, type:const(mcp)}
- GooseExtensionEntry { extension:GooseExtension, enabled:boolean, configKey?:string|null }
- GooseSessionUpdate = SessionUsageUpdate | StatusMessageUpdate | MessageUsageUpdate | LiveVoiceInteractionEndedUpdate
- HttpHeader { name:string, value:string, _meta?:object|null }
- ImageContent { annotations?:Annotations|null, data:string, mimeType:string, uri?:string|null, _meta?:object|null }
- LiveVoiceInteractionEndedUpdate { interactionId:string, outcome:LiveVoiceInteractionOutcome }
- LiveVoiceInteractionOutcome = enum(stopped,failed)
- LiveVoiceStatus = enum(ready,unavailable)
- LocalInferenceChatTemplate = {type:const(embedded)} | {name:string, type:const(builtin)} | {template:string, type:const(custom_inline)}
- LocalInferenceDownloadProgressDto { modelId:string, status:string, bytesDownloaded:integer, totalBytes:integer, progressPercent:number, speedBps?:integer|null, etaSeconds?:integer|null, error?:string|null, taskExited:boolean }
- LocalInferenceDownloadState = enum(NotDownloaded,Downloading,Downloaded)
- LocalInferenceHfGgufFileDto { filename:string, sizeBytes:integer, quantization:string, downloadUrl:string }
- LocalInferenceHfModelInfoDto { repoId:string, author:string, modelName:string, downloads:integer, ggufFiles?:[LocalInferenceHfGgufFileDto], variants?:[LocalInferenceHfModelVariantDto] }
- LocalInferenceHfModelVariantDto { variantId:string, label:string, backendId:string, format:string, modelId:string, downloadId:string, sizeBytes:integer, filename?:string|null, downloadUrl?:string|null, description:string, qualityRank:integer, sharded:boolean, supported:boolean, unsupportedReason?:string|null }
- LocalInferenceModelDownloadStatusDto { state:LocalInferenceDownloadState, progressPercent?:number|null, bytesDownloaded?:integer|null, totalBytes?:integer|null, speedBps?:integer|null }
- LocalInferenceModelDto { id:string, repoId:string, filename:string, quantization:string, sizeBytes:integer, status:LocalInferenceModelDownloadStatusDto, recommended:boolean, isLoaded:boolean, settings:LocalInferenceModelSettingsDto, visionCapable:boolean, mmprojStatus?:LocalInferenceModelDownloadStatusDto|null }
- LocalInferenceModelSettingsDto { backendId?:string|null, contextSize?:integer|null, maxOutputTokens?:integer|null, draftModel?:string|null, sampling?:LocalInferenceSamplingConfig, repeatPenalty:number, repeatLastN:integer, frequencyPenalty:number, presencePenalty:number, nBatch?:integer|null, nGpuLayers?:integer|null, useMlock:boolean, flashAttention?:boolean|null, nThreads?:integer|null, toolCalling?:LocalInferenceToolCallingMode, chatTemplate?:LocalInferenceChatTemplate, enableThinking:boolean, visionCapable:boolean, imageTokenEstimate:integer, mmprojSizeBytes:integer }
- LocalInferenceSamplingConfig = {type:const(Greedy)} | {temperature:number, topK:integer, topP:number, minP:number, seed:integer|null, type:const(Temperature)} | {tau:number, eta:number, seed:integer|null, type:const(MirostatV2)}
- LocalInferenceToolCallingMode = enum(auto,force_native,force_emulated)
- McpServer = McpServerHttp | McpServerSse | McpServerStdio
- McpServerHttp { name:string, url:string, headers:[HttpHeader], _meta?:object|null, type:const(http) }
- McpServerSse { name:string, url:string, headers:[HttpHeader], _meta?:object|null, type:const(sse) }
- McpServerStdio { name:string, command:string, args:[string], env:[EnvVariable], _meta?:object|null }
- MessageUsageData { inputTokens?:integer|null, outputTokens?:integer|null, totalTokens?:integer|null, cacheReadTokens?:integer|null, cacheWriteTokens?:integer|null, cost?:number|null, costSource?:CostSourceData|null, elapsedMs?:integer|null, timeToFirstTokenMs?:integer|null, isCompaction?:boolean }
- MessageUsageUpdate { messageId?:string|null, usage:MessageUsageData }
- OnboardingImportCandidate { id:string, sourceKind:OnboardingImportSourceKind, displayName:string, path:string, counts:OnboardingImportCounts, warnings?:[string] }
- OnboardingImportCounts { providers:integer, extensions:integer, sessions:integer, skills:integer, projects:integer, preferences:integer }
- OnboardingImportSourceKind = enum(goose_config,claude_desktop)
- PreferenceKey = enum(autoCompactThreshold,gooseThinkingEffort,voiceAutoSubmitPhrases,voiceDictationProvider,voiceDictationPreferredMic)
- PreferenceValue { key:PreferenceKey, value?:None }
- PromptTemplateEntry { name:string, description:string, defaultContent:string, userContent?:string|null, isCustomized:boolean }
- ProviderConfigFieldUpdate { key:string, value:string }
- ProviderConfigFieldValueDto { key:string, value?:string|null, isSet:boolean, isSecret:boolean, required:boolean }
- ProviderConfigKey { name:string, required:boolean, secret:boolean, default?:string|null, oauthFlow?:boolean, deviceCodeFlow?:boolean, primary?:boolean }
- ProviderConfigStatusDto { providerId:string, isConfigured:boolean }
- ProviderInventoryEntryDto { providerId:string, providerName:string, description:string, defaultModel:string, configured:boolean, available:boolean, providerType:string, acp?:boolean, visibleInSetup:boolean, deprecated:boolean, replacement?:string|null, configKeys:[ProviderConfigKey], setupSteps:[string], supportsRefresh:boolean, refreshing:boolean, models:[ProviderInventoryModelDto], lastUpdatedAt?:string|null, lastRefreshAttemptAt?:string|null, lastRefreshError?:string|null, stale:boolean }
- ProviderInventoryModelDto { id:string, name:string, family?:string|null, contextLimit?:integer|null, reasoning?:boolean|null, recommended?:boolean }
- ProviderSecretDto { id:string, provider:string, providerDisplayName:string, name:string, storage:ProviderSecretStorageDto, expiresAt?:string|null, status:ProviderSecretStatusDto, configured:boolean, hasSecret:boolean, canDelete:boolean, canConfigure:boolean, configureProvider?:string|null }
- ProviderSecretStatusDto = enum(valid,expired,unknown)
- ProviderSecretStorageDto = enum(secret_store,provider_cache)
- ProviderSetupCatalogEntryDto { providerId:string, name:string, category:ProviderSetupCategoryDto, acp?:boolean, description:string, setupMethod:ProviderSetupMethodDto, nativeConnectQuery?:string|null, fields?:[ProviderSetupFieldDto], binaryName?:string|null, docUrl?:string|null, group:ProviderSetupGroupDto, showOnlyWhenInstalled:boolean, aliases?:[string], supportsInstall:boolean, supportsAuth:boolean, supportsAuthStatus:boolean }
- ProviderSetupCategoryDto = enum(agent,model)
- ProviderSetupFieldDto { key:string, label:string, secret:boolean, required:boolean, placeholder?:string|null, defaultValue?:string|null }
- ProviderSetupGroupDto = enum(default,additional)
- ProviderSetupMethodDto = enum(none,single_api_key,config_fields,host_with_oauth_fallback,oauth_browser,oauth_device_code,cloud_credentials,local,cli_auth)
- ProviderTemplateCapabilitiesDto { toolCall:boolean, reasoning:boolean, attachment:boolean, temperature:boolean }
- ProviderTemplateCatalogEntryDto { providerId:string, name:string, format:string, apiUrl:string, modelCount:integer, docUrl:string, envVar:string }
- ProviderTemplateDto { providerId:string, name:string, format:string, apiUrl:string, models:[ProviderTemplateModelDto], supportsStreaming:boolean, envVar:string, docUrl:string }
- ProviderTemplateModelDto { id:string, name:string, contextLimit:integer, capabilities:ProviderTemplateCapabilitiesDto, deprecated:boolean }
- RecipeAuthorDto { contact?:string|null, metadata?:string|null }
- RecipeDto { version?:string, title:string, description:string, instructions?:string|null, prompt?:string|null, extensions?:array|null, settings?:RecipeSettingsDto|null, activities?:array|null, author?:RecipeAuthorDto|null, parameters?:array|null, response?:RecipeResponseDto|null, sub_recipes?:array|null, retry?:RecipeRetryConfigDto|null }
- RecipeListEntryDto { id:string, recipe:RecipeDto, file_path:string, last_modified:string, schedule_cron?:string|null, slash_command?:string|null }
- RecipeParameterDto { key:string, input_type:RecipeParameterInputTypeDto, requirement:RecipeParameterRequirementDto, description:string, default?:string|null, options?:array|null }
- RecipeParameterInputTypeDto = enum(string,number,boolean,date,file,select)
- RecipeParameterRequirementDto = enum(required,optional,user_prompt)
- RecipeParamsAction = enum(submit,cancel)
- RecipeResponseDto { json_schema?:None }
- RecipeRetryConfigDto { max_retries:integer, checks?:[RecipeSuccessCheckDto], on_failure?:string|null, timeout_seconds?:integer|null, on_failure_timeout_seconds?:integer|null }
- RecipeSettingsDto { goose_provider?:string|null, goose_model?:string|null, temperature?:number|null, max_turns?:integer|null }
- RecipeSuccessCheckDto = {command:string, type:const(shell)}
- RefreshProviderInventorySkipDto { providerId:string, reason:RefreshProviderInventorySkipReasonDto }
- RefreshProviderInventorySkipReasonDto = enum(unknown_provider,not_configured,does_not_support_refresh,already_refreshing)
- ResourceLink { annotations?:Annotations|null, description?:string|null, mimeType?:string|null, name:string, size?:integer|null, title?:string|null, uri:string, _meta?:object|null }
- RunScheduleNowStatus = enum(completed,cancelled)
- ScheduledJobDto { id:string, source:string, cron:string, lastRun?:string|null, currentlyRunning:boolean, paused:boolean, currentSessionId?:string|null, jobStartTime?:string|null }
- SessionExportFormat = enum(json,markdown)
- SessionExtensionEntry { extension:GooseExtension, extensionKey:string }
- SessionId = string
- SessionInfo { sessionId:SessionId, cwd:string, additionalDirectories?:[string], title?:string|null, updatedAt?:string|null, _meta?:object|null }
- SessionSystemPromptMode = const(set) | const(append)
- SessionUsageUpdate { used:integer, contextLimit:integer, accumulatedInputTokens:integer, accumulatedOutputTokens:integer, accumulatedCost?:number|null }
- SourceEntry { type:SourceType, name:string, description:string, content:string, path:string, global:boolean, writable?:boolean, supportingFiles?:[string], properties?:map<None> }
- SourceScope = {scope:const(global)} | {projectDir:string, scope:const(projectDir)} | {projectId:string, scope:const(projectId)}
- SourceType = enum(skill,builtinSkill,recipe,subrecipe,agent,project)
- StatusMessage = {message:string, type:const(notice)} | {message:string, type:const(progress)}
- StatusMessageUpdate { status:StatusMessage }
- TextContent { annotations?:Annotations|null, text:string, _meta?:object|null }
- TextResourceContents { mimeType?:string|null, text:string, uri:string, _meta?:object|null }
- ToolListItem { name:string, description:string, parameters:[string], permission?:ToolPermissionLevel|null, inputSchema:None, outputSchema?:None }
- ToolPermissionEntry { toolName:string, permission:ToolPermissionLevel }
- ToolPermissionLevel = enum(always_allow,ask_before,never_allow)
- UnstructuredCommandInput { hint:string, _meta?:object|null }