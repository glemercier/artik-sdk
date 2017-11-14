/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#include <artik_module.h>
#include <artik_platform.h>
#include <artik_loop.h>
#include <artik_log.h>

#include <artik_lwm2m.h>
#include <artik_list.h>
#include "os_lwm2m.h"
#include "lwm2mclient.h"

#include <pthread.h>
#include <sched.h>

enum lwm2m_connection_state {
	LWM2M_INIT,
	LWM2M_CONNECT,
	LWM2M_EXIT,
};

typedef struct {
	artik_list node;

	object_container_t *container;
	client_handle_t *client;
	artik_lwm2m_callback callbacks[ARTIK_LWM2M_EVENT_COUNT];
	void *callbacks_params[ARTIK_LWM2M_EVENT_COUNT];

	enum lwm2m_connection_state state;
	bool use_se;
	pthread_t thread_id;
	pthread_mutex_t mutex;
} lwm2m_node;

typedef struct {
	lwm2m_node *node;
	artik_lwm2m_event_t event;
	void *extra;
	int id;
} lwm2m_event_params;

static artik_list *nodes = NULL;

static void *_lwm2m_service_thread(void *user_data)
{
	lwm2m_node *node = (lwm2m_node *)user_data;
	int timeout;

	log_dbg("");
	while (node->state == LWM2M_CONNECT) {
		timeout = lwm2m_client_service(node->client, 100);

		if (timeout < LWM2M_CLIENT_OK) {
			pthread_mutex_lock(&(node->mutex));
			node->state = LWM2M_EXIT;
			if (node->callbacks[ARTIK_LWM2M_EVENT_ERROR]) {
				artik_error err = (timeout == LWM2M_CLIENT_QUIT)
					? E_INTERRUPTED : E_LWM2M_ERROR;
				node->callbacks[ARTIK_LWM2M_EVENT_ERROR](
					(void *)err,
					node->callbacks_params[
						ARTIK_LWM2M_EVENT_ERROR]);
			}
			pthread_mutex_unlock(&(node->mutex));
		}
	}

	pthread_mutex_lock(&(node->mutex));
	lwm2m_client_stop(node->client);
	node->client = NULL;
	pthread_mutex_unlock(&(node->mutex));
	pthread_exit(0);
}

static int on_lwm2m_event(lwm2m_event_params *params)
{
	if (params) {
		pthread_mutex_lock(&params->node->mutex);
		if (params->node->callbacks[params->event]) {
			params->node->callbacks[params->event](params->extra,
					params->node->callbacks_params[
						params->event]);
		}
		pthread_mutex_unlock(&params->node->mutex);
	}

	return 0;
}

static void on_exec_factory_reset(void *user_data, void *extra)
{
	lwm2m_node *node = (lwm2m_node *)user_data;

	log_dbg("");

	if (node->callbacks[ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE]) {
		lwm2m_event_params *params = malloc(sizeof(lwm2m_event_params));

		params->node = node;
		params->extra = (void *)strndup(LWM2M_URI_DEVICE_FACTORY_RESET,
				strlen(LWM2M_URI_DEVICE_FACTORY_RESET));
		params->event = ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE;

		on_lwm2m_event(params);
		free(params->extra);
		free(params);
	}
}

static void on_exec_device_reboot(void *user_data, void *extra)
{
	lwm2m_node *node = (lwm2m_node *)user_data;

	log_dbg("");

	if (node->callbacks[ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE]) {
		lwm2m_event_params *params = malloc(sizeof(lwm2m_event_params));

		params->node = node;
		params->extra = (void *)strndup(LWM2M_URI_DEVICE_REBOOT,
				strlen(LWM2M_URI_DEVICE_REBOOT));
		params->event = ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE;

		on_lwm2m_event(params);
		free(params->extra);
		free(params);
	}
}

static void on_exec_firmware_update(void *user_data, void *extra)
{
	lwm2m_node *node = (lwm2m_node *)user_data;

	log_dbg("");

	if (node->callbacks[ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE]) {
		lwm2m_event_params *params = malloc(sizeof(lwm2m_event_params));

		params->node = node;
		params->extra = (void *)strndup(LWM2M_URI_FIRMWARE_UPDATE,
				strlen(LWM2M_URI_FIRMWARE_UPDATE));
		params->event = ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE;

		on_lwm2m_event(params);
		free(params->extra);
		free(params);
	}
}

static void on_resource_changed(void *user_data, void *extra)
{
	lwm2m_node *node = (lwm2m_node *)user_data;
	lwm2m_resource_t *res = (lwm2m_resource_t *)extra;

	log_dbg("uri: %s", res->uri);

	if (node->callbacks[ARTIK_LWM2M_EVENT_RESOURCE_CHANGED]) {
		lwm2m_event_params *params = malloc(sizeof(lwm2m_event_params));
		artik_lwm2m_resource_t resource;

		params->node = node;
		resource.uri = res->uri;
		resource.buffer = res->buffer;
		resource.length = res->length;
		params->extra = (void *)&resource;
		params->event = ARTIK_LWM2M_EVENT_RESOURCE_CHANGED;

		on_lwm2m_event(params);
		free(params);
	}
}

artik_error os_lwm2m_client_request(artik_lwm2m_handle *handle,
				artik_lwm2m_config *config)
{
	lwm2m_node *node = NULL;
	object_container_t *objects = NULL;
	object_security_server_t *server = NULL;
	artik_error ret = S_OK;
	int i;
	bool use_se = false;

	log_dbg("");

	if (!config || !config->server_uri || !config->name)
		return E_BAD_ARGS;

	node = (lwm2m_node *) artik_list_add(&nodes, 0, sizeof(lwm2m_node));
	objects = malloc(sizeof(object_container_t));
	server = malloc(sizeof(object_security_server_t));

	if (!node || !objects || !server)
		return E_NO_MEM;

	memset(objects, 0, sizeof(object_container_t));
	memset(server, 0, sizeof(object_security_server_t));
	node->state = LWM2M_INIT;

	/* Fill up server object based on passed config */
	strncpy(server->serverUri, config->server_uri, LWM2M_MAX_STR_LEN);
	strncpy(server->client_name, config->name, LWM2M_MAX_STR_LEN);
	server->securityMode = LWM2M_SEC_MODE_PSK;

	if (config->ssl_config) {
		if (!config->tls_psk_key) {
			artik_list_delete_node(&nodes, (artik_list *)node);
			ret = E_BAD_ARGS;
			goto error;
		}

		server->verifyCert = config->ssl_config->verify_cert == ARTIK_SSL_VERIFY_REQUIRED;
		node->use_se = config->ssl_config->se_config.use_se;

		if (!config->ssl_config->se_config.use_se
			&& config->ssl_config->client_cert.data && config->ssl_config->client_cert.len
			&& config->ssl_config->client_key.data && config->ssl_config->client_key.len) {
			server->clientCertificateOrPskId = strdup(config->ssl_config->client_cert.data);
			server->privateKey = strdup(config->ssl_config->client_key.data);
			server->securityMode = LWM2M_SEC_MODE_CERT;
		} else if (config->ssl_config->se_config.use_se) {
			artik_security_module *security =
				(artik_security_module *)artik_request_api_module("security");
			artik_security_handle sec_handle = NULL;
			if (!security) {
				log_dbg("Unable to request security module");
				ret = E_SECURITY_ERROR;
				goto error;
			}

			ret = security->request(&sec_handle);
			if (ret != S_OK) {
				log_dbg("Unable to request security handle");
				artik_release_api_module(security);
				goto error;
			}

			ret = security->get_certificate(sec_handle, CERT_ID_ARTIK,
					&server->clientCertificateOrPskId);
			if (ret != S_OK) {
				security->release(sec_handle);
				artik_release_api_module(security);
				log_dbg("Unable to get certificate (err %d)", ret);
				goto error;
			}

			ret = security->get_key_from_cert(sec_handle, server->clientCertificateOrPskId, &server->privateKey);
			if (ret != S_OK) {
				security->release(sec_handle);
				artik_release_api_module(security);
				log_dbg("Unable to get certificate (err %d)", ret);
				goto error;
			}

			use_se = true;
			server->securityMode = LWM2M_SEC_MODE_CERT;
			security->release(sec_handle);
			artik_release_api_module(security);
		} else if (!config->ssl_config->client_cert.data && !config->ssl_config->client_cert.len
				   && !config->ssl_config->client_key.data && !config->ssl_config->client_key.len) {
			if (!config->tls_psk_identity) {
				ret = E_BAD_ARGS;
				goto error;
			}

			server->clientCertificateOrPskId = strdup(config->tls_psk_identity);
			log_dbg("Copy PSK parameters (%s/%s)", config->tls_psk_identity,
					config->tls_psk_key);
		} else {
			ret = E_BAD_ARGS;
			goto error;
		}

		strncpy(server->token, config->tls_psk_key, LWM2M_MAX_STR_LEN);
		if (config->ssl_config->ca_cert.data)
			server->serverCertificate = strdup(config->ssl_config->ca_cert.data);
	} else if (config->tls_psk_identity && config->tls_psk_key) {
		log_dbg("Copy PSK parameters (%s/%s)", config->tls_psk_identity,
			config->tls_psk_key);
		server->clientCertificateOrPskId = strdup(config->tls_psk_identity);
		strncpy(server->token, config->tls_psk_key, LWM2M_MAX_STR_LEN);
	}

	server->lifetime = config->lifetime;
	server->serverId = config->server_id;
	objects->server = server;

	/* Copy objects if they have been provided */
	for (i = 0; i < ARTIK_LWM2M_OBJECT_COUNT; i++) {
		if (!config->objects[i])
			continue;

		if (!config->objects[i]->content)
			continue;

		switch (config->objects[i]->type) {
		case ARTIK_LWM2M_OBJECT_DEVICE:
			objects->device = malloc(sizeof(object_device_t));
			if (!objects->device) {
				ret = E_NO_MEM;
				goto error;
			}
			memcpy(objects->device, config->objects[i]->content, sizeof(object_device_t));
			break;
		case ARTIK_LWM2M_OBJECT_CONNECTIVITY_MONITORING:
			objects->monitoring = malloc(sizeof(object_conn_monitoring_t));
			if (!objects->monitoring) {
				ret = E_NO_MEM;
				goto error;
			}
			memcpy(objects->monitoring, config->objects[i]->content,sizeof(object_conn_monitoring_t));
			break;
		case ARTIK_LWM2M_OBJECT_FIRMWARE:
			objects->firmware = malloc(sizeof(object_firmware_t));
			if (!objects->firmware) {
				ret = E_NO_MEM;
				goto error;
			}
			memcpy(objects->firmware, config->objects[i]->content, sizeof(object_firmware_t));
			break;
		default:
			log_err("Unknown object");
			break;
		}
	}

	pthread_mutexattr_t mutexattr;
	if (pthread_mutexattr_init(&mutexattr) != 0) {
		log_err("Failed to initialize lwm2m mutex attribute");
		ret = E_LWM2M_ERROR;
		goto error;
	}
	if (pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE))
	{
		log_err("Failed to set the lwm2m mutex type");
		pthread_mutexattr_destroy(&mutexattr);
		ret = E_LWM2M_ERROR;
		goto error;
	}
	if (pthread_mutex_init(&node->mutex, &mutexattr) != 0) {
		log_err("Failed to initialize lwm2m mutex");
		pthread_mutexattr_destroy(&mutexattr);
		ret = E_LWM2M_ERROR;
		goto error;
	}

	node->container = objects;
	log_dbg("node->container %p", node->container);
	*handle = (artik_lwm2m_handle)node;
	pthread_mutexattr_destroy(&mutexattr);

	return S_OK;

error:
	artik_list_delete_node(&nodes, (artik_list *)node);

	if (server) {
		if (server->serverCertificate)
			free(server->serverCertificate);

		if (server->clientCertificateOrPskId)
			free(server->clientCertificateOrPskId);

		if (server->privateKey)
			free(server->privateKey);

		free(server);
	}

	if (objects) {
		if (objects->device)
			free(objects->device);

		if (objects->firmware)
			free(objects->firmware);

		if (objects->monitoring)
			free(objects->monitoring);

		free(objects);
	}
	return ret;
}

artik_error os_lwm2m_client_connect(artik_lwm2m_handle handle)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes, (ARTIK_LIST_HANDLE) handle);
	artik_error ret = S_OK;
	pthread_attr_t thread_attr;

	log_dbg("");

	if (!node)
		return E_BAD_ARGS;

	if (!node->container) {
		log_dbg("node container is null");
		return E_BAD_ARGS;
	}

	/* Configure and start the client */
	node->client = lwm2m_client_start(node->container, node->container->server->serverCertificate, node->use_se);
	if (!node->client) {
		log_err("Failed to start lwm2m client");
		ret = E_LWM2M_ERROR;
		goto error;
	}

	lwm2m_register_callback(node->client, LWM2M_EXE_FACTORY_RESET,
				on_exec_factory_reset,
				(void *)node);
	lwm2m_register_callback(node->client, LWM2M_EXE_DEVICE_REBOOT,
				on_exec_device_reboot,
				(void *)node);
	lwm2m_register_callback(node->client, LWM2M_EXE_FIRMWARE_UPDATE,
				on_exec_firmware_update,
				(void *)node);
	lwm2m_register_callback(node->client,
				LWM2M_NOTIFY_RESOURCE_CHANGED,
				on_resource_changed,
				(void *)node);

	/* Start timeout callback to service the LWM2M library */
	if (pthread_attr_init(&thread_attr) != 0) {
		log_err("Failed to initialize lwm2m thread attribute.");
		pthread_mutex_destroy(&node->mutex);
		ret = E_LWM2M_ERROR;
		goto error;
	}
	if (pthread_attr_setstacksize(&thread_attr, 16*1024) != 0) {
		log_err("Failed to set lwm2m thread stack size.");
		pthread_mutex_destroy(&node->mutex);
		pthread_attr_destroy(&thread_attr);
		ret = E_LWM2M_ERROR;
		goto error;
	}

	node->state = LWM2M_CONNECT;
	if (pthread_create(&node->thread_id, &thread_attr,
					_lwm2m_service_thread, node) != 0) {
		log_err("Failed to create lwm2m thread");
		pthread_mutex_destroy(&node->mutex);
		pthread_attr_destroy(&thread_attr);
		ret = E_LWM2M_ERROR;
		goto error;
	}
	pthread_attr_destroy(&thread_attr);
	pthread_setname_np(node->thread_id, "LWM2M daemon");
	struct sched_param param;

	param.sched_priority = 105;
	pthread_setschedparam(node->thread_id, SCHED_RR, &param);

	return S_OK;

error:
	if (node->client) {
		lwm2m_client_stop(node->client);
		node->client = NULL;
	}

	return ret;
}

artik_error os_lwm2m_client_disconnect(artik_lwm2m_handle handle)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
						(ARTIK_LIST_HANDLE) handle);

	log_dbg("");

	if (!node)
		return E_BAD_ARGS;

	pthread_mutex_lock(&node->mutex);
	if (node->state != LWM2M_CONNECT) {
		pthread_mutex_unlock(&node->mutex);
		return E_NOT_CONNECTED;
	}

	node->state = LWM2M_EXIT;
	pthread_mutex_unlock(&node->mutex);

	pthread_join(node->thread_id, NULL);

	return S_OK;
}

artik_error os_lwm2m_client_release(artik_lwm2m_handle handle) {
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
						(ARTIK_LIST_HANDLE) handle);

	log_dbg("");

	if (!node)
		return E_BAD_ARGS;

	pthread_mutex_lock(&node->mutex);
	if (node->state == LWM2M_CONNECT) {
		pthread_mutex_unlock(&node->mutex);
		return E_LWM2M_ERROR;
	}
	pthread_mutex_unlock(&node->mutex);

	pthread_mutex_destroy(&node->mutex);

	if (node->container) {
		if (node->container->server) {
			if (node->container->server->serverCertificate)
				free(node->container->server->serverCertificate);

			if (node->container->server->clientCertificateOrPskId)
				free(node->container->server->clientCertificateOrPskId);

			if (node->container->server->privateKey)
				free(node->container->server->privateKey);

			free(node->container->server);
		}

		if (node->container->device)
			free(node->container->device);

		if (node->container->firmware)
			free(node->container->firmware);

		if (node->container->monitoring)
			free(node->container->monitoring);

		free(node->container);
	}

	artik_list_delete_node(&nodes, (artik_list *)node);
	return S_OK;
}

artik_error os_lwm2m_client_write_resource(artik_lwm2m_handle handle,
		const char *uri, unsigned char *buffer, int length)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
						(ARTIK_LIST_HANDLE) handle);
	lwm2m_resource_t res;
	artik_error ret = S_OK;

	log_dbg("");

	if (!node || !uri)
		return E_BAD_ARGS;

	pthread_mutex_lock(&node->mutex);

	if (node->state != LWM2M_CONNECT) {
		ret = E_NOT_CONNECTED;
		goto exit;
	}

	strncpy(res.uri, uri, LWM2M_MAX_URI_LEN);
	res.length = length;
	res.buffer = buffer;

	if (lwm2m_write_resource(node->client, &res) != LWM2M_CLIENT_OK) {
		log_err("Failed to write resource %s", res.uri);
		ret = E_LWM2M_ERROR;
		goto exit;
	}

exit:
	pthread_mutex_unlock(&node->mutex);
	return ret;
}

artik_error os_lwm2m_client_read_resource(artik_lwm2m_handle handle,
		const char *uri, unsigned char *buffer, int *length)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
						(ARTIK_LIST_HANDLE) handle);
	lwm2m_resource_t res;
	artik_error ret = S_OK;

	log_dbg("");

	if (!node || !uri || !buffer || (*length == 0))
		return E_BAD_ARGS;

	memset(&res, 0, sizeof(res));
	strncpy(res.uri, uri, LWM2M_MAX_URI_LEN);

	pthread_mutex_lock(&node->mutex);

	if (node->state != LWM2M_CONNECT) {
		ret = E_NOT_CONNECTED;
		goto exit;
	}

	if (lwm2m_read_resource(node->client, &res)) {
		log_err("Failed to read resource %s", res.uri);
		pthread_mutex_unlock(&node->mutex);
		return E_LWM2M_ERROR;
	}

	pthread_mutex_unlock(&node->mutex);

	if (res.length > *length) {
		log_err("Buffer is too small");
		ret = E_NO_MEM;
		goto exit;
	}

	*length = res.length;
	memcpy(buffer, res.buffer, res.length);

exit:
	if (res.buffer)
		free(res.buffer);

	return ret;
}

artik_error os_lwm2m_set_callback(artik_lwm2m_handle handle,
		artik_lwm2m_event_t event,
		artik_lwm2m_callback user_callback, void *user_data)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
						(ARTIK_LIST_HANDLE) handle);

	log_dbg("");

	if (!node || !user_callback || (event >= ARTIK_LWM2M_EVENT_COUNT))
		return E_BAD_ARGS;

	pthread_mutex_lock(&node->mutex);
	node->callbacks[event] = user_callback;
	node->callbacks_params[event] = user_data;
	pthread_mutex_unlock(&node->mutex);

	return S_OK;
}

artik_error os_lwm2m_unset_callback(artik_lwm2m_handle handle,
				artik_lwm2m_event_t event)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
					(ARTIK_LIST_HANDLE) handle);

	log_dbg("");

	if (!node || (event >= ARTIK_LWM2M_EVENT_COUNT))
		return E_BAD_ARGS;

	pthread_mutex_lock(&node->mutex);
	node->callbacks[event] = NULL;
	node->callbacks_params[event] = NULL;
	pthread_mutex_unlock(&node->mutex);

	return S_OK;
}

artik_lwm2m_object *os_lwm2m_create_device_object(const char *manufacturer,
		const char *model, const char *serial, const char *fw_version,
		const char *hw_version, const char *sw_version,
		const char *device_type, int power_source, int power_volt,
		int power_current, int battery_level, int memory_total,
		int memory_free, const char *time_zone, const char *utc_offset,
		const char *binding)
{
	artik_lwm2m_object *obj = NULL;
	object_device_t *content = NULL;

	log_dbg("");

	obj = malloc(sizeof(*obj));
	if (!obj) {
		log_err("Not enough memory to allocate LWM2M object");
		return NULL;
	}

	memset(obj, 0, sizeof(*obj));
	obj->type = ARTIK_LWM2M_OBJECT_DEVICE;

	content = malloc(sizeof(object_device_t));
	if (!content) {
		log_err("Not enough memory to allocate LWM2M object content");
		free(obj);
		return NULL;
	}

	memset(content, 0, sizeof(*content));

	if (manufacturer)
		strncpy(content->manufacturer, manufacturer, LWM2M_MAX_STR_LEN);

	if (model)
		strncpy(content->model_number, model, LWM2M_MAX_STR_LEN);

	if (serial)
		strncpy(content->serial_number, serial, LWM2M_MAX_STR_LEN);

	if (fw_version)
		strncpy(content->firmware_version, fw_version,
			LWM2M_MAX_STR_LEN);

	if (hw_version)
		strncpy(content->hardware_version, hw_version,
			LWM2M_MAX_STR_LEN);

	if (sw_version)
		strncpy(content->software_version, sw_version,
			LWM2M_MAX_STR_LEN);

	if (device_type)
		strncpy(content->device_type, device_type, LWM2M_MAX_STR_LEN);

	content->power_source_1 = power_source;
	content->power_voltage_1 = power_volt;
	content->power_current_1 = power_current;
	content->battery_level = battery_level;
	content->memory_total = memory_total;
	content->memory_free = memory_free;

	if (time_zone)
		strncpy(content->time_zone, time_zone, LWM2M_MAX_STR_LEN);

	if (utc_offset)
		strncpy(content->utc_offset, utc_offset, LWM2M_MAX_STR_LEN);

	if (binding)
		strncpy(content->binding_mode, binding, LWM2M_MAX_STR_LEN);

	obj->content = (void *)content;

	return obj;
}

artik_lwm2m_object *os_lwm2m_create_firmware_object(bool supported,
				char *pkg_name, char *pkg_version) {
	artik_lwm2m_object *obj = NULL;
	object_firmware_t *content = NULL;

	log_dbg("");

	obj = malloc(sizeof(artik_lwm2m_object));
	if (!obj) {
		log_err("Not enough memory to allocate LWM2M object");
		return NULL;
	}
	memset(obj, 0, sizeof(artik_lwm2m_object));
	obj->type = ARTIK_LWM2M_OBJECT_FIRMWARE;

	content = malloc(sizeof(object_firmware_t));
	if (!content) {
		log_err("Not enough memory to allocale LWM2M object content");
		free(obj);
		return NULL;
	}

	memset(content, 0, sizeof(object_firmware_t));
	content->supported = supported;

	if (pkg_name)
		strncpy(content->pkg_name, pkg_name, LWM2M_MAX_STR_LEN);

	if (pkg_version)
		strncpy(content->pkg_version, pkg_version, LWM2M_MAX_STR_LEN);

	obj->content = (void *)content;
	return obj;
}

artik_lwm2m_object *os_lwm2m_create_connectivity_monitoring_object(
		int netbearer, int avlnetbearer, int signalstrength,
		int linkquality, int lenip, const char **ipaddr, int lenroute,
		const char **routeaddr, int linkutilization, const char *apn,
		int cellid, int smnc, int smcc)
{
	artik_lwm2m_object *obj = NULL;
	object_conn_monitoring_t *content = NULL;

	log_dbg("");

	obj = malloc(sizeof(*obj));
	if (!obj) {
		log_err("Not enough memory to allocate LWM2M object");
		return NULL;
	}

	memset(obj, 0, sizeof(*obj));
	obj->type = ARTIK_LWM2M_OBJECT_CONNECTIVITY_MONITORING;

	content = malloc(sizeof(object_device_t));
	if (!content) {
		log_err("Not enough memory to allocate LWM2M object content");
		free(obj);
		return NULL;
	}

	memset(content, 0, sizeof(*content));

	content->avl_network_bearer = netbearer;
	content->radio_signal_strength = avlnetbearer;
	content->link_quality = signalstrength;
	content->link_utilization = linkquality;
	content->cell_id = cellid;
	content->smnc = smnc;
	content->smcc = smcc;
	if (ipaddr && lenip >= 1 && ipaddr[0])
		strncpy(content->ip_addr2, ipaddr[0], LWM2M_MAX_STR_LEN);
	if (ipaddr && lenip >= 2 && ipaddr[1])
		strncpy(content->ip_addr2, ipaddr[1], LWM2M_MAX_STR_LEN);
	if (routeaddr && lenroute >= 1 && routeaddr[0])
		strncpy(content->router_ip_addr, routeaddr[0],
				LWM2M_MAX_STR_LEN);
	if (routeaddr && lenroute >= 2 && routeaddr[1])
		strncpy(content->router_ip_addr2, routeaddr[1],
				LWM2M_MAX_STR_LEN);
	if (apn)
		strncpy(content->apn, apn, LWM2M_MAX_STR_LEN);

	obj->content = (void *)content;
	return obj;
}


void os_lwm2m_free_object(artik_lwm2m_object *object)
{
	log_dbg("");

	if (object) {
		if (object->content)
			free(object->content);
		free(object);
	}
}

artik_error os_serialize_tlv_int(int *data, int size, unsigned char **buffer,
				int *lenbuffer)
{
	lwm2m_resource_t resource_serialized;

	if (size <= 0 || data == NULL)
		return E_BAD_ARGS;
	if (lwm2m_serialize_tlv_int(size, data, &resource_serialized) ==
							LWM2M_CLIENT_ERROR) {
		log_err("Can't serialize data of type 'array of integer',\n"
			"got an error from lwm2m.");
		return E_LWM2M_ERROR;
	}
	*lenbuffer = resource_serialized.length;
	if (resource_serialized.length < 1)
		return E_INVALID_VALUE;
	*buffer = resource_serialized.buffer;
	return S_OK;
}

artik_error os_serialize_tlv_string(char **data, int size,
				unsigned char **buffer, int *lenbuffer)
{
	lwm2m_resource_t resource_serialized;

	if (size <= 0 || data == NULL)
		return E_BAD_ARGS;
	if (lwm2m_serialize_tlv_string(size, data, &resource_serialized) ==
							LWM2M_CLIENT_ERROR) {
		log_err("Can't serialize data of type 'array of string',\n"
			"got an error from lwm2m.");
		return E_LWM2M_ERROR;
	}
	*lenbuffer = resource_serialized.length;
	if (resource_serialized.length < 1)
		return E_INVALID_VALUE;
	*buffer = resource_serialized.buffer;
	return S_OK;
}
