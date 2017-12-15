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

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <artik_log.h>
#include "../mqtt_client.h"

#include <mosquitto.h>
#include <apps/netutils/mqtt_api.h>

typedef struct {
	artik_list node;
	artik_mqtt_config *config;
	mqtt_client_t *client;
	mqtt_client_config_t client_config;
	mqtt_tls_param_t tls_config;

	void *data_cb_connect;
	void *data_cb_disconnect;
	void *data_cb_subscribe;
	void *data_cb_unsubscribe;
	void *data_cb_publish;
	void *data_cb_message;

	connect_callback on_connect;
	disconnect_callback on_disconnect;
	subscribe_callback on_subscribe;
	unsubscribe_callback on_unsubscribe;
	publish_callback on_publish;
	message_callback on_message;
} mqtt_handle_client;

static artik_list *requested_node = NULL;

static void on_connect_callback(void *client, int result)
{
	mqtt_handle_client *client_data = (mqtt_handle_client *)
			(((mqtt_client_t *)client)->config->user_data);

	log_dbg("");

	if (client_data && client_data->on_connect)
		client_data->on_connect(client_data->config,
			client_data->data_cb_connect,
			result ? E_MQTT_ERROR : S_OK);
}

static void on_disconnect_callback(void *client, int result)
{
	mqtt_handle_client *client_data = (mqtt_handle_client *)
			(((mqtt_client_t *)client)->config->user_data);

	log_dbg("");

	if (client_data && client_data->on_disconnect)
		client_data->on_disconnect(client_data->config,
				client_data->data_cb_disconnect,
				result ? E_MQTT_ERROR : S_OK);
}

static void on_subscribe_callback(void *client, int mid, int qos_count,
		const int *granted_qos)
{
	mqtt_handle_client *client_data = (mqtt_handle_client *)
			(((mqtt_client_t *)client)->config->user_data);

	log_dbg("");

	if (client_data && client_data->on_subscribe)
		client_data->on_subscribe(client_data->config,
			client_data->data_cb_subscribe, mid, qos_count,
			granted_qos);
}

static void on_unsubscribe_callback(void *client, int mid)
{
	mqtt_handle_client *client_data = (mqtt_handle_client *)
			(((mqtt_client_t *)client)->config->user_data);

	log_dbg("");

	if (client_data && client_data->on_unsubscribe)
		client_data->on_unsubscribe(client_data->config,
			client_data->data_cb_unsubscribe, mid);
}

static void on_publish_callback(void *client, int mid)
{
	mqtt_handle_client *client_data = (mqtt_handle_client *)
			(((mqtt_client_t *)client)->config->user_data);

	log_dbg("");

	if (client_data && client_data->on_publish)
		client_data->on_publish(client_data->config,
			client_data->data_cb_publish, mid);
}

static void on_message_callback(void *client, mqtt_msg_t *msg)
{
	mqtt_handle_client *client_data = (mqtt_handle_client *)
			(((mqtt_client_t *)client)->config->user_data);
	artik_mqtt_msg *received_msg;

	log_dbg("");

	received_msg = (artik_mqtt_msg *) malloc(sizeof(artik_mqtt_msg));
	if (!received_msg) {
		log_err("Failed to allocate memory for received message");
		return;
	}

	received_msg->msg_id = msg->msg_id;
	received_msg->topic = msg->topic;
	received_msg->payload = msg->payload;
	received_msg->payload_len = msg->payload_len;
	received_msg->qos = msg->qos;
	received_msg->retain = msg->retain;

	if (client_data && client_data->on_message)
		client_data->on_message(client_data->config,
			client_data->data_cb_message, received_msg);

	free(received_msg);
}

artik_mqtt_handle mqtt_create_client(artik_mqtt_config *config)
{
	mqtt_handle_client *mqtt_client = NULL;

	log_dbg("");

	mqtt_client = (mqtt_handle_client *)artik_list_add(&requested_node, 0,
			sizeof(mqtt_handle_client));
	if (!mqtt_client) {
		log_err("Failed to allocate memory for MQTT client");
		return NULL;
	}

	mqtt_client->node.handle = (ARTIK_LIST_HANDLE)mqtt_client;
	mqtt_client->config = config;

	memset(&mqtt_client->client_config, 0, sizeof(mqtt_client->client_config));
	mqtt_client->client_config.user_data = (void *)mqtt_client;
	mqtt_client->client_config.protocol_version = MQTT_PROTOCOL_V31;
	mqtt_client->client_config.debug = 1;
	mqtt_client->client_config.client_id = (char *)config->client_id;
	mqtt_client->client_config.user_name = (char *)config->user_name;
	mqtt_client->client_config.password = (char *)config->pwd;
	mqtt_client->client_config.clean_session = config->clean_session;
	mqtt_client->client_config.on_connect = on_connect_callback;
	mqtt_client->client_config.on_disconnect = on_disconnect_callback;
	mqtt_client->client_config.on_publish = on_publish_callback;
	mqtt_client->client_config.on_message = on_message_callback;
	mqtt_client->client_config.on_subscribe = on_subscribe_callback;
	mqtt_client->client_config.on_unsubscribe = on_unsubscribe_callback;

	if (config->tls) {
		memset(&mqtt_client->tls_config, 0, sizeof(mqtt_client->tls_config));
		if (config->tls->verify_cert == ARTIK_SSL_VERIFY_REQUIRED) {
			mqtt_client->tls_config.cert = (const unsigned char *)
					config->tls->client_cert.data;
			mqtt_client->tls_config.cert_len = config->tls->client_cert.len;
			mqtt_client->tls_config.key = (const unsigned char *)
					config->tls->client_key.data;
			mqtt_client->tls_config.key_len = config->tls->client_key.len;
			mqtt_client->tls_config.ca_cert = (const unsigned char *)
					config->tls->ca_cert.data;
			mqtt_client->tls_config.ca_cert_len = config->tls->ca_cert.len;
		}
		mqtt_client->client_config.tls = &mqtt_client->tls_config;
	}

	mqtt_client->client = mqtt_init_client(&mqtt_client->client_config);
	if (!mqtt_client->client) {
		log_err("Failed to initialize MQTT client");
		artik_list_delete_node(&requested_node, (artik_list *)mqtt_client);
		return NULL;
	}

	return (artik_mqtt_handle)mqtt_client;
}

int mqtt_client_set_willmsg(artik_mqtt_config *config, const char *willtopic,
			const char *willmsg, int qos, bool retain)
{
	artik_mqtt_msg *will_msg;

	log_dbg("");

	if (config && willtopic && willmsg && qos <= 2 && qos >= 0) {
		if (config->will_msg != NULL)
			mqtt_client_free_willmsg(config);
		config->will_msg = (artik_mqtt_msg *)
						malloc(sizeof(artik_mqtt_msg));
		if (!config->will_msg)
			return -MQTT_ERROR_NOMEM;

		will_msg = config->will_msg;
		will_msg->topic = (char *) malloc(strlen(willtopic) + 1);
		if (!will_msg->topic)
			return -MQTT_ERROR_NOMEM;
		strncpy(will_msg->topic, willtopic, strlen(willtopic));
		will_msg->payload = (char *) malloc(strlen(willmsg) + 1);
		if (!will_msg->payload)
			return -MQTT_ERROR_NOMEM;
		strncpy(will_msg->payload, willmsg, strlen(willmsg));
		will_msg->payload_len = strlen(willmsg);
		will_msg->qos = qos;
		will_msg->retain = retain;
	} else
		return -MQTT_ERROR_PARAM;

	return MQTT_ERROR_SUCCESS;
}

void mqtt_client_destroy_client(artik_mqtt_handle handle)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node, (ARTIK_LIST_HANDLE)handle);

	log_dbg("");

	if (client) {
		mqtt_deinit_client(client->client);
		artik_list_delete_node(&requested_node, (artik_list *)handle);
	}
}

int mqtt_client_free_willmsg(artik_mqtt_config *config)
{
	log_dbg("");

	if (config && config->will_msg) {
		if (config->will_msg->topic) {
			free(config->will_msg->topic);
			config->will_msg->topic = NULL;
		}
		if (config->will_msg->payload) {
			free(config->will_msg->payload);
			config->will_msg->payload = NULL;
		}
		free(config->will_msg);
		config->will_msg = NULL;
	}

	return MQTT_ERROR_SUCCESS;
}

int mqtt_client_clear_willmsg(artik_mqtt_handle handle_client)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);

	int rc = -1;

	log_dbg("");

	if (client && client->client && client->client->mosq) {
		mqtt_client_free_willmsg(client->config);
		rc = mosquitto_will_clear(client->client->mosq);
		if (rc != MOSQ_ERR_SUCCESS)
			return -MQTT_ERROR_LIB;
		else
			return MQTT_ERROR_SUCCESS;
	} else {
		return -MQTT_ERROR_PARAM;
	}
}

int mqtt_client_set_connect(artik_mqtt_handle handle_client, connect_callback cb,
			void *user_connect_data)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);

	if (!client)
		return -MQTT_ERROR_PARAM;
	client->on_connect = cb;
	client->data_cb_connect = user_connect_data;
	return MQTT_ERROR_SUCCESS;
}

int mqtt_client_set_disconnect(artik_mqtt_handle handle_client,
		disconnect_callback cb,	void *user_disconnect_data)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);

	if (!client)
		return -MQTT_ERROR_PARAM;
	client->on_disconnect = cb;
	client->data_cb_disconnect = user_disconnect_data;
	return MQTT_ERROR_SUCCESS;
}

int mqtt_client_set_subscribe(artik_mqtt_handle handle_client,
		subscribe_callback cb, void *user_subscribe_data)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);

	if (!client)
		return -MQTT_ERROR_PARAM;
	client->on_subscribe = cb;
	client->data_cb_subscribe = user_subscribe_data;
	return MQTT_ERROR_SUCCESS;
}

int mqtt_client_set_unsubscribe(artik_mqtt_handle handle_client,
		unsubscribe_callback cb, void *user_unsubscribe_data)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);

	if (!client)
		return -MQTT_ERROR_PARAM;
	client->on_unsubscribe = cb;
	client->data_cb_unsubscribe = user_unsubscribe_data;
	return MQTT_ERROR_SUCCESS;
}

int mqtt_client_set_publish(artik_mqtt_handle handle_client,
		publish_callback cb, void *user_publish_data)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);

	if (!client)
		return -MQTT_ERROR_PARAM;
	client->on_publish = cb;
	client->data_cb_publish = user_publish_data;
	return MQTT_ERROR_SUCCESS;
}

int mqtt_client_set_message(artik_mqtt_handle handle_client,
		message_callback cb, void *user_message_data)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);

	if (!client)
		return -MQTT_ERROR_PARAM;
	client->on_message = cb;
	client->data_cb_message = user_message_data;
	return MQTT_ERROR_SUCCESS;
}

int mqtt_client_connect(artik_mqtt_handle handle_client, const char *host,
		int port)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);
	int rc = 0;

	log_dbg("");

	if (!client)
		return -MQTT_ERROR_PARAM;

	rc = mqtt_connect(client->client, (char *)host, port,
			client->config->keep_alive_time / 1000);

	return rc ? -MQTT_ERROR_LIB : MQTT_ERROR_SUCCESS;
}

int mqtt_client_disconnect(artik_mqtt_handle handle_client)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);
	int rc = 0;

	log_dbg("");

	rc = mqtt_disconnect(client->client);

	return rc ? -MQTT_ERROR_LIB : MQTT_ERROR_SUCCESS;
}

int mqtt_client_subscribe(artik_mqtt_handle handle_client, int qos,
		const char *msgtopic)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);
	int rc = 0;

	log_dbg("");

	if (qos < 0 || qos > 2)
		return -MQTT_ERROR_PARAM;

	if (!msgtopic || !client)
		return -MQTT_ERROR_PARAM;

	rc = mqtt_subscribe(client->client, (char *)msgtopic, qos);

	return rc ? -MQTT_ERROR_LIB : MQTT_ERROR_SUCCESS;
}

int mqtt_client_unsubscribe(artik_mqtt_handle handle_client,
		const char *msg_topic)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);
	int rc = 0;

	log_dbg("");

	if (!client || !msg_topic)
		return -MQTT_ERROR_PARAM;

	rc = mqtt_unsubscribe(client->client, (char *)msg_topic);

	return rc ? -MQTT_ERROR_LIB : MQTT_ERROR_SUCCESS;
}

int mqtt_client_publish(artik_mqtt_handle handle_client, int qos, bool retain,
		const char *msg_topic, int payload_len, const char *msg_content)
{
	mqtt_handle_client *client = (mqtt_handle_client *)
		artik_list_get_by_handle(requested_node,
			(ARTIK_LIST_HANDLE)handle_client);
	int rc = 0;

	log_dbg("");

	if (qos < 0 || qos > 2)
		return -MQTT_ERROR_PARAM;

	if (!client || !msg_topic || payload_len == 0 || !msg_content)
		return -MQTT_ERROR_PARAM;

	rc = mqtt_publish(client->client, (char *)msg_topic, (char *)msg_content,
			payload_len, qos, retain);

	return rc ? -MQTT_ERROR_LIB : MQTT_ERROR_SUCCESS;
}
