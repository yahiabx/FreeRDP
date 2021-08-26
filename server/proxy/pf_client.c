/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server
 *
 * Copyright 2019 Mati Shabtay <matishabtay@gmail.com>
 * Copyright 2019 Kobi Mizrachi <kmizrachi18@gmail.com>
 * Copyright 2019 Idan Freiberg <speidy@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/client/cmdline.h>

#include <freerdp/server/proxy/proxy_log.h>

#include "pf_channels.h"
#include "pf_gdi.h"
#include "pf_graphics.h"
#include "pf_client.h"
#include <freerdp/server/proxy/proxy_context.h>
#include "pf_update.h"
#include "pf_input.h"
#include "pf_config.h"
#include "proxy_modules.h"

#define TAG PROXY_TAG("client")

static BOOL proxy_server_reactivate(rdpContext* ps, const rdpContext* pc)
{
	WINPR_ASSERT(ps);
	WINPR_ASSERT(pc);

	if (!pf_context_copy_settings(ps->settings, pc->settings))
		return FALSE;

	/*
	 * DesktopResize causes internal function rdp_server_reactivate to be called,
	 * which causes the reactivation.
	 */
	WINPR_ASSERT(ps->update);
	if (!ps->update->DesktopResize(ps))
		return FALSE;

	return TRUE;
}

static void pf_client_on_error_info(void* ctx, ErrorInfoEventArgs* e)
{
	pClientContext* pc = (pClientContext*)ctx;
	pServerContext* ps;

	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	WINPR_ASSERT(e);
	ps = pc->pdata->ps;
	WINPR_ASSERT(ps);

	if (e->code == ERRINFO_NONE)
		return;

	PROXY_LOG_WARN(TAG, pc, "received ErrorInfo PDU. code=0x%08" PRIu32 ", message: %s", e->code,
	               freerdp_get_error_info_string(e->code));

	/* forward error back to client */
	freerdp_set_error_info(ps->context.rdp, e->code);
	freerdp_send_error_info(ps->context.rdp);
}

static void pf_client_on_activated(void* ctx, ActivatedEventArgs* e)
{
	pClientContext* pc = (pClientContext*)ctx;
	pServerContext* ps;
	freerdp_peer* peer;

	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	WINPR_ASSERT(e);

	ps = pc->pdata->ps;
	WINPR_ASSERT(ps);
	peer = ps->context.peer;
	WINPR_ASSERT(peer);

	PROXY_LOG_INFO(TAG, pc, "client activated, registering server input callbacks");

	/* Register server input/update callbacks only after proxy client is fully activated */
	pf_server_register_input_callbacks(peer->input);
	pf_server_register_update_callbacks(peer->update);
}

static BOOL pf_client_load_rdpsnd(pClientContext* pc)
{
	rdpContext* context = (rdpContext*)pc;
	pServerContext* ps;
	const proxyConfig* config;

	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	ps = pc->pdata->ps;
	WINPR_ASSERT(ps);
	config = pc->pdata->config;
	WINPR_ASSERT(config);

	/*
	 * if AudioOutput is enabled in proxy and client connected with rdpsnd, use proxy as rdpsnd
	 * backend. Otherwise, use sys:fake.
	 */
	if (!freerdp_static_channel_collection_find(context->settings, RDPSND_CHANNEL_NAME))
	{
		char* params[2];
		params[0] = RDPSND_CHANNEL_NAME;

		if (config->AudioOutput &&
		    WTSVirtualChannelManagerIsChannelJoined(ps->vcm, RDPSND_CHANNEL_NAME))
			params[1] = "sys:proxy";
		else
			params[1] = "sys:fake";

		if (!freerdp_client_add_static_channel(context->settings, 2, (char**)params))
			return FALSE;
	}

	return TRUE;
}

static BOOL pf_client_passthrough_channels_init(pClientContext* pc)
{
	pServerContext* ps;
	rdpSettings* settings;
	const proxyConfig* config;
	size_t i;

	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	ps = pc->pdata->ps;
	WINPR_ASSERT(ps);
	settings = pc->context.settings;
	WINPR_ASSERT(settings);
	config = pc->pdata->config;
	WINPR_ASSERT(config);

	if (settings->ChannelCount + config->PassthroughCount >= settings->ChannelDefArraySize)
	{
		PROXY_LOG_ERR(TAG, pc, "too many channels");
		return FALSE;
	}

	for (i = 0; i < config->PassthroughCount; i++)
	{
		const char* channel_name = config->Passthrough[i];
		CHANNEL_DEF channel = { 0 };

		/* only connect connect this channel if already joined in peer connection */
		if (!WTSVirtualChannelManagerIsChannelJoined(ps->vcm, channel_name))
		{
			PROXY_LOG_INFO(TAG, ps,
			               "client did not connected with channel %s, skipping passthrough",
			               channel_name);

			continue;
		}

		channel.options = CHANNEL_OPTION_INITIALIZED; /* TODO: Export to config. */
		strncpy(channel.name, channel_name, CHANNEL_NAME_LEN);

		freerdp_settings_set_pointer_array(settings, FreeRDP_ChannelDefArray,
		                                   settings->ChannelCount++, &channel);
	}

	return TRUE;
}

static BOOL pf_client_use_peer_load_balance_info(pClientContext* pc)
{
	pServerContext* ps;
	rdpSettings* settings;
	DWORD lb_info_len;
	const char* lb_info;

	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	ps = pc->pdata->ps;
	WINPR_ASSERT(ps);
	settings = pc->context.settings;
	WINPR_ASSERT(settings);

	lb_info = freerdp_nego_get_routing_token(&ps->context, &lb_info_len);
	if (!lb_info)
		return TRUE;

	free(settings->LoadBalanceInfo);

	settings->LoadBalanceInfoLength = lb_info_len;
	settings->LoadBalanceInfo = malloc(settings->LoadBalanceInfoLength);

	if (!settings->LoadBalanceInfo)
		return FALSE;

	CopyMemory(settings->LoadBalanceInfo, lb_info, settings->LoadBalanceInfoLength);
	return TRUE;
}

static BOOL pf_client_pre_connect(freerdp* instance)
{
	pClientContext* pc;
	pServerContext* ps;
	const proxyConfig* config;
	rdpSettings* settings;

	WINPR_ASSERT(instance);
	pc = (pClientContext*)instance->context;
	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	ps = pc->pdata->ps;
	WINPR_ASSERT(ps);
	WINPR_ASSERT(ps->pdata);
	config = ps->pdata->config;
	WINPR_ASSERT(config);
	settings = instance->settings;
	WINPR_ASSERT(settings);

	/*
	 * as the client's settings are copied from the server's, GlyphSupportLevel might not be
	 * GLYPH_SUPPORT_NONE. the proxy currently do not support GDI & GLYPH_SUPPORT_CACHE, so
	 * GlyphCacheSupport must be explicitly set to GLYPH_SUPPORT_NONE.
	 *
	 * Also, OrderSupport need to be zeroed, because it is currently not supported.
	 */
	settings->GlyphSupportLevel = GLYPH_SUPPORT_NONE;
	ZeroMemory(settings->OrderSupport, 32);

	settings->SupportDynamicChannels = TRUE;

	/* Multimon */
	settings->UseMultimon = TRUE;

	/* Sound */
	settings->AudioPlayback = FALSE;
	settings->DeviceRedirection = TRUE;

	/* Display control */
	settings->SupportDisplayControl = config->DisplayControl;
	settings->DynamicResolutionUpdate = config->DisplayControl;

	settings->AutoReconnectionEnabled = TRUE;

	/**
	 * Register the channel listeners.
	 * They are required to set up / tear down channels if they are loaded.
	 */
	PubSub_SubscribeChannelConnected(instance->context->pubSub,
	                                 pf_channels_on_client_channel_connect);
	PubSub_SubscribeChannelDisconnected(instance->context->pubSub,
	                                    pf_channels_on_client_channel_disconnect);
	PubSub_SubscribeErrorInfo(instance->context->pubSub, pf_client_on_error_info);
	PubSub_SubscribeActivated(instance->context->pubSub, pf_client_on_activated);
	/**
	 * Load all required plugins / channels / libraries specified by current
	 * settings.
	 */
	PROXY_LOG_INFO(TAG, pc, "Loading addins");

	if (!pf_client_use_peer_load_balance_info(pc))
		return FALSE;

	if (!pf_client_passthrough_channels_init(pc))
		return FALSE;

	if (!pf_client_load_rdpsnd(pc))
	{
		PROXY_LOG_ERR(TAG, pc, "Failed to load rdpsnd client");
		return FALSE;
	}

	if (!freerdp_client_load_addins(instance->context->channels, instance->settings))
	{
		PROXY_LOG_ERR(TAG, pc, "Failed to load addins");
		return FALSE;
	}

	return TRUE;
}

static BOOL pf_client_receive_channel_data_hook(freerdp* instance, UINT16 channelId,
                                                const BYTE* data, size_t size, UINT32 flags,
                                                size_t totalSize)
{
	const char* channel_name = freerdp_channels_get_name_by_id(instance, channelId);
	pClientContext* pc;
	pServerContext* ps;
	proxyData* pdata;
	const proxyConfig* config;
	size_t i;

	WINPR_ASSERT(instance);
	WINPR_ASSERT(data || (size == 0));

	pc = (pClientContext*)instance->context;
	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);

	ps = pc->pdata->ps;
	WINPR_ASSERT(ps);

	pdata = ps->pdata;
	WINPR_ASSERT(pdata);

	config = pdata->config;
	WINPR_ASSERT(config);

	for (i = 0; i < config->PassthroughCount; i++)
	{
		const char* cname = config->Passthrough[i];
		if (strncmp(channel_name, cname, CHANNEL_NAME_LEN + 1) == 0)
		{
			proxyChannelDataEventInfo ev;
			UINT16 server_channel_id;

			ev.channel_id = channelId;
			ev.channel_name = channel_name;
			ev.data = data;
			ev.data_len = size;

			if (!pf_modules_run_filter(pdata->module, FILTER_TYPE_CLIENT_PASSTHROUGH_CHANNEL_DATA,
			                           pdata, &ev))
				return FALSE;

			server_channel_id = WTSChannelGetId(ps->context.peer, channel_name);
			return ps->context.peer->SendChannelData(ps->context.peer, server_channel_id, data,
			                                         size);
		}
	}

	WINPR_ASSERT(pc->client_receive_channel_data_original);
	return pc->client_receive_channel_data_original(instance, channelId, data, size, flags,
	                                                totalSize);
}

static BOOL pf_client_on_server_heartbeat(freerdp* instance, BYTE period, BYTE count1, BYTE count2)
{
	pClientContext* pc;
	pServerContext* ps;

	WINPR_ASSERT(instance);
	pc = (pClientContext*)instance->context;
	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	ps = pc->pdata->ps;
	WINPR_ASSERT(ps);

	return freerdp_heartbeat_send_heartbeat_pdu(ps->context.peer, period, count1, count2);
}

static BOOL pf_client_send_channel_data(pClientContext* pc, const proxyChannelDataEventInfo* ev)
{
	WINPR_ASSERT(pc);
	WINPR_ASSERT(ev);

	if (!pc->connected)
	{
		ArrayList_Append(pc->cached_server_channel_data, ev);
		return TRUE;
	}
	else
	{
		UINT16 channelId = freerdp_channels_get_id_by_name(pc->context.instance, ev->channel_name);
		WINPR_ASSERT(channelId > 0);
		WINPR_ASSERT(channelId < UINT16_MAX);
		return pc->context.instance->SendChannelData(pc->context.instance, channelId, ev->data,
		                                             ev->data_len);
	}
}

static BOOL send_channel_data(void* data, size_t index, va_list ap)
{
	pClientContext* pc = va_arg(ap, pClientContext*);
	proxyChannelDataEventInfo* ev = data;
	WINPR_ASSERT(ev);
	WINPR_ASSERT(pc);
	WINPR_UNUSED(index);

	return pf_client_send_channel_data(pc, ev);
}

/**
 * Called after a RDP connection was successfully established.
 * Settings might have changed during negotiation of client / server feature
 * support.
 *
 * Set up local framebuffers and painting callbacks.
 * If required, register pointer callbacks to change the local mouse cursor
 * when hovering over the RDP window
 */
static BOOL pf_client_post_connect(freerdp* instance)
{
	rdpContext* context;
	rdpSettings* settings;
	rdpUpdate* update;
	rdpContext* ps;
	pClientContext* pc;
	const proxyConfig* config;

	WINPR_ASSERT(instance);
	context = instance->context;
	WINPR_ASSERT(context);
	settings = instance->settings;
	WINPR_ASSERT(settings);
	update = instance->update;
	WINPR_ASSERT(update);
	pc = (pClientContext*)context;
	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	ps = (rdpContext*)pc->pdata->ps;
	WINPR_ASSERT(ps);
	config = pc->pdata->config;
	WINPR_ASSERT(config);

	if (!pf_modules_run_hook(pc->pdata->module, HOOK_TYPE_CLIENT_POST_CONNECT, pc->pdata))
		return FALSE;

	if (!gdi_init(instance, PIXEL_FORMAT_BGRA32))
		return FALSE;

	if (!pf_register_pointer(context->graphics))
		return FALSE;

	if (!settings->SoftwareGdi)
	{
		if (!pf_register_graphics(context->graphics))
		{
			PROXY_LOG_ERR(TAG, pc, "failed to register graphics");
			return FALSE;
		}

		pf_gdi_register_update_callbacks(update);
		brush_cache_register_callbacks(update);
		glyph_cache_register_callbacks(update);
		bitmap_cache_register_callbacks(update);
		offscreen_cache_register_callbacks(update);
		palette_cache_register_callbacks(update);
	}

	pf_client_register_update_callbacks(update);

	/* virtual channels receive data hook */
	pc->client_receive_channel_data_original = instance->ReceiveChannelData;
	instance->ReceiveChannelData = pf_client_receive_channel_data_hook;

	instance->heartbeat->ServerHeartbeat = pf_client_on_server_heartbeat;

	pc->connected = TRUE;

	/* Send cached channel data */
	ArrayList_Lock(pc->cached_server_channel_data);
	ArrayList_ForEach(pc->cached_server_channel_data, send_channel_data, pc);
	ArrayList_Clear(pc->cached_server_channel_data);
	ArrayList_Unlock(pc->cached_server_channel_data);

	/*
	 * after the connection fully established and settings were negotiated with target server,
	 * send a reactivation sequence to the client with the negotiated settings. This way,
	 * settings are synchorinized between proxy's peer and and remote target.
	 */
	return proxy_server_reactivate(ps, context);
}

/* This function is called whether a session ends by failure or success.
 * Clean up everything allocated by pre_connect and post_connect.
 */
static void pf_client_post_disconnect(freerdp* instance)
{
	pClientContext* context;
	proxyData* pdata;

	if (!instance)
		return;

	if (!instance->context)
		return;

	context = (pClientContext*)instance->context;
	WINPR_ASSERT(context);
	pdata = context->pdata;
	WINPR_ASSERT(pdata);

	PubSub_UnsubscribeChannelConnected(instance->context->pubSub,
	                                   pf_channels_on_client_channel_connect);
	PubSub_UnsubscribeChannelDisconnected(instance->context->pubSub,
	                                      pf_channels_on_client_channel_disconnect);
	PubSub_UnsubscribeErrorInfo(instance->context->pubSub, pf_client_on_error_info);
	gdi_free(instance);

	/* Only close the connection if NLA fallback process is done */
	if (!context->allow_next_conn_failure)
		proxy_data_abort_connect(pdata);
}

/*
 * pf_client_should_retry_without_nla:
 *
 * returns TRUE if in case of connection failure, the client should try again without NLA.
 * Otherwise, returns FALSE.
 */
static BOOL pf_client_should_retry_without_nla(pClientContext* pc)
{
	rdpSettings* settings;
	const proxyConfig* config;

	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	settings = pc->context.settings;
	WINPR_ASSERT(settings);
	config = pc->pdata->config;
	WINPR_ASSERT(config);

	if (!config->ClientAllowFallbackToTls || !settings->NlaSecurity)
		return FALSE;

	return config->ClientTlsSecurity || config->ClientRdpSecurity;
}

static void pf_client_set_security_settings(pClientContext* pc)
{
	rdpSettings* settings;
	const proxyConfig* config;

	WINPR_ASSERT(pc);
	WINPR_ASSERT(pc->pdata);
	settings = pc->context.settings;
	WINPR_ASSERT(settings);
	config = pc->pdata->config;
	WINPR_ASSERT(config);

	settings->RdpSecurity = config->ClientRdpSecurity;
	settings->TlsSecurity = config->ClientTlsSecurity;
	settings->NlaSecurity = FALSE;

	if (!config->ClientNlaSecurity)
		return;

	if (!settings->Username || !settings->Password)
		return;

	settings->NlaSecurity = TRUE;
}

static BOOL pf_client_connect_without_nla(pClientContext* pc)
{
	freerdp* instance;
	rdpSettings* settings;

	WINPR_ASSERT(pc);
	instance = pc->context.instance;
	WINPR_ASSERT(instance);
	settings = pc->context.settings;
	WINPR_ASSERT(settings);
	/* disable NLA */
	settings->NlaSecurity = FALSE;

	/* do not allow next connection failure */
	pc->allow_next_conn_failure = FALSE;
	return freerdp_connect(instance);
}

static BOOL pf_client_connect(freerdp* instance)
{
	pClientContext* pc;
	rdpSettings* settings;
	BOOL rc = FALSE;
	BOOL retry = FALSE;

	WINPR_ASSERT(instance);
	pc = (pClientContext*)instance->context;
	WINPR_ASSERT(pc);
	settings = instance->settings;
	WINPR_ASSERT(settings);

	PROXY_LOG_INFO(TAG, pc, "connecting using client info: Username: %s, Domain: %s",
	               settings->Username, settings->Domain);

	pf_client_set_security_settings(pc);
	if (pf_client_should_retry_without_nla(pc))
		retry = pc->allow_next_conn_failure = TRUE;

	PROXY_LOG_INFO(TAG, pc, "connecting using security settings: rdp=%d, tls=%d, nla=%d",
	               settings->RdpSecurity, settings->TlsSecurity, settings->NlaSecurity);

	if (!freerdp_connect(instance))
	{
		if (!retry)
			goto out;

		PROXY_LOG_ERR(TAG, pc, "failed to connect with NLA. retrying to connect without NLA");
		pf_modules_run_hook(pc->pdata->module, HOOK_TYPE_CLIENT_LOGIN_FAILURE, pc->pdata);

		if (!pf_client_connect_without_nla(pc))
		{
			PROXY_LOG_ERR(TAG, pc, "pf_client_connect_without_nla failed!");
			goto out;
		}
	}

	rc = TRUE;
out:
	pc->allow_next_conn_failure = FALSE;
	return rc;
}

/**
 * RDP main loop.
 * Connects RDP, loops while running and handles event and dispatch, cleans up
 * after the connection ends.
 */
static DWORD WINAPI pf_client_thread_proc(LPVOID arg)
{
	freerdp* instance = (freerdp*)arg;
	pClientContext* pc;
	proxyData* pdata;
	DWORD nCount = 0;
	DWORD status;
	HANDLE handles[65] = { 0 };

	WINPR_ASSERT(instance);
	pc = (pClientContext*)instance->context;
	WINPR_ASSERT(pc);
	pdata = pc->pdata;
	WINPR_ASSERT(pdata);
	/*
	 * during redirection, freerdp's abort event might be overriden (reset) by the library, after
	 * the server set it in order to shutdown the connection. it means that the server might signal
	 * the client to abort, but the library code will override the signal and the client will
	 * continue its work instead of exiting. That's why the client must wait on `pdata->abort_event`
	 * too, which will never be modified by the library.
	 */
	handles[nCount++] = pdata->abort_event;

	if (!pf_modules_run_hook(pdata->module, HOOK_TYPE_CLIENT_PRE_CONNECT, pdata))
	{
		proxy_data_abort_connect(pdata);
		return FALSE;
	}

	if (!pf_client_connect(instance))
	{
		proxy_data_abort_connect(pdata);
		return FALSE;
	}

	while (!freerdp_shall_disconnect(instance))
	{
		UINT32 tmp = freerdp_get_event_handles(instance->context, &handles[nCount],
		                                       ARRAYSIZE(handles) - nCount);

		if (tmp == 0)
		{
			PROXY_LOG_ERR(TAG, pc, "freerdp_get_event_handles failed!");
			break;
		}

		status = WaitForMultipleObjects(nCount + tmp, handles, FALSE, INFINITE);

		if (status == WAIT_FAILED)
		{
			WLog_ERR(TAG, "%s: WaitForMultipleObjects failed with %" PRIu32 "", __FUNCTION__,
			         status);
			break;
		}

		/* abort_event triggered */
		if (status == WAIT_OBJECT_0)
			break;

		if (freerdp_shall_disconnect(instance))
			break;

		if (proxy_data_shall_disconnect(pdata))
			break;

		if (!freerdp_check_event_handles(instance->context))
		{
			if (freerdp_get_last_error(instance->context) == FREERDP_ERROR_SUCCESS)
				WLog_ERR(TAG, "Failed to check FreeRDP event handles");

			break;
		}
	}

	freerdp_disconnect(instance);
	return 0;
}

static int pf_logon_error_info(freerdp* instance, UINT32 data, UINT32 type)
{
	const char* str_data = freerdp_get_logon_error_info_data(data);
	const char* str_type = freerdp_get_logon_error_info_type(type);

	if (!instance || !instance->context)
		return -1;

	WLog_INFO(TAG, "Logon Error Info %s [%s]", str_data, str_type);
	return 1;
}

static void pf_client_context_free(freerdp* instance, rdpContext* context)
{
	pClientContext* pc = (pClientContext*)context;

	if (!pc)
		return;

	ArrayList_Free(pc->cached_server_channel_data);
}

static void* channel_data_copy(const void* obj)
{
	const proxyChannelDataEventInfo* src = obj;
	proxyChannelDataEventInfo* dst;

	WINPR_ASSERT(src);

	dst = calloc(1, sizeof(proxyChannelDataEventInfo));
	WINPR_ASSERT(dst);

	*dst = *src;
	if (src->channel_name)
	{
		dst->channel_name = _strdup(src->channel_name);
		WINPR_ASSERT(dst->channel_name);
	}
	dst->data = malloc(src->data_len);
	WINPR_ASSERT(dst->data);
	memcpy((void*)dst->data, src->data, src->data_len);
	return dst;
}

static void channel_data_free(void* obj)
{
	proxyChannelDataEventInfo* dst = obj;
	if (dst)
	{
		free((void*)dst->data);
		free((void*)dst->channel_name);
		free(dst);
	}
}

static BOOL pf_client_client_new(freerdp* instance, rdpContext* context)
{
	wObject* obj;
	pClientContext* pc = (pClientContext*)context;

	if (!instance || !context)
		return FALSE;

	instance->PreConnect = pf_client_pre_connect;
	instance->PostConnect = pf_client_post_connect;
	instance->PostDisconnect = pf_client_post_disconnect;
	instance->LogonErrorInfo = pf_logon_error_info;
	instance->ContextFree = pf_client_context_free;

	pc->sendChannelData = pf_client_send_channel_data;
	pc->cached_server_channel_data = ArrayList_New(TRUE);
	if (!pc->cached_server_channel_data)
		return FALSE;
	obj = ArrayList_Object(pc->cached_server_channel_data);
	WINPR_ASSERT(obj);
	obj->fnObjectNew = channel_data_copy;
	obj->fnObjectFree = channel_data_free;
	return TRUE;
}

static int pf_client_client_stop(rdpContext* context)
{
	pClientContext* pc = (pClientContext*)context;
	proxyData* pdata;

	WINPR_ASSERT(pc);
	pdata = pc->pdata;
	WINPR_ASSERT(pdata);

	PROXY_LOG_DBG(TAG, pc, "aborting client connection");
	proxy_data_abort_connect(pdata);
	freerdp_abort_connect(context->instance);

	if (pdata->client_thread)
	{
		/*
		 * Wait for client thread to finish. No need to call CloseHandle() here, as
		 * it is the responsibility of `proxy_data_free`.
		 */
		PROXY_LOG_DBG(TAG, pc, "waiting for client thread to finish");
		WaitForSingleObject(pdata->client_thread, INFINITE);
		PROXY_LOG_DBG(TAG, pc, "thread finished");
	}

	return 0;
}

int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints)
{
	WINPR_ASSERT(pEntryPoints);

	ZeroMemory(pEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
	pEntryPoints->Version = RDP_CLIENT_INTERFACE_VERSION;
	pEntryPoints->Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	pEntryPoints->ContextSize = sizeof(pClientContext);
	/* Client init and finish */
	pEntryPoints->ClientNew = pf_client_client_new;
	pEntryPoints->ClientStop = pf_client_client_stop;
	return 0;
}

/**
 * Starts running a client connection towards target server.
 */
DWORD WINAPI pf_client_start(LPVOID arg)
{
	rdpContext* context = (rdpContext*)arg;

	WINPR_ASSERT(context);
	if (freerdp_client_start(context) != 0)
		return 1;

	return pf_client_thread_proc(context->instance);
}
