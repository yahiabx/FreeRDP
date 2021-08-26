/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server
 *
 * Copyright 2021 Armin Novak <armin.novak@thincast.com>
 * Copyright 2021 Thincast Technologies GmbH
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
#ifndef FREERDP_SERVER_PROXY_CONFIG_H
#define FREERDP_SERVER_PROXY_CONFIG_H

#include <winpr/ini.h>

#include <freerdp/api.h>

typedef struct proxy_config proxyConfig;

#ifdef __cplusplus
extern "C"
{
#endif
	FREERDP_API BOOL pf_config_get_uint16(wIniFile* ini, const char* section, const char* key,
	                                      UINT16* result);
	FREERDP_API BOOL pf_config_get_uint32(wIniFile* ini, const char* section, const char* key,
	                                      UINT32* result);
	FREERDP_API BOOL pf_config_get_bool(wIniFile* ini, const char* section, const char* key);
	FREERDP_API const char* pf_config_get_str(wIniFile* ini, const char* section, const char* key);

	FREERDP_API proxyConfig* pf_server_config_load_file(const char* path);
	FREERDP_API proxyConfig* pf_server_config_load_buffer(const char* buffer);
	FREERDP_API void pf_server_config_print(const proxyConfig* config);
	FREERDP_API void pf_server_config_free(proxyConfig* config);

#ifdef __cplusplus
};
#endif
#endif /* FREERDP_SERVER_PROXY_CONFIG_H */
