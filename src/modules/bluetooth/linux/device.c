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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <gio/gio.h>
#pragma GCC diagnostic pop

#include "core.h"

static void _set_trusted(const char *device_path, gboolean value)
{
	GVariant *result;
	GError *error = NULL;

	result = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		device_path,
		DBUS_IF_PROPERTIES,
		"Set",
		g_variant_new("(ssv)", DBUS_IF_DEVICE1, "Trusted",
			g_variant_new_boolean(value)),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &error);

	if (bt_check_error(error) != S_OK)
		return;

	g_variant_unref(result);
}

static void _set_blocked(const char *device_path, gboolean value)
{
	GVariant *result;
	GError *error = NULL;

	result = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		device_path,
		DBUS_IF_PROPERTIES,
		"Set",
		g_variant_new("(ssv)", DBUS_IF_DEVICE1,
				"Blocked", g_variant_new_boolean(value)),
		NULL, G_DBUS_CALL_FLAGS_NONE,
		G_MAXINT, NULL, &error);

	if (bt_check_error(error) != S_OK)
		return;

	g_variant_unref(result);
}

artik_error bt_remove_unpaired_devices(void)
{
	artik_bt_device *device_list = NULL;
	int count = 0;
	int i = 0;
	artik_error ret = S_OK;

	log_dbg("%s", __func__);

	ret = _get_devices(BT_DEVICE_STATE_IDLE, &device_list, &count);
	if (ret != S_OK)
		return ret;

	for (i = 0; i < count; i++) {
		if (!bt_is_paired(device_list[i].remote_address)
			|| !bt_is_connected(device_list[i].remote_address))

			bt_remove_device(device_list[i].remote_address);
	}

	bt_free_devices(&device_list, count);

	return S_OK;
}

artik_error bt_remove_devices(void)
{
	artik_bt_device *device_list = NULL;
	int count = 0;
	int i = 0;
	artik_error ret = S_OK;

	log_dbg("");

	ret = _get_devices(BT_DEVICE_STATE_IDLE, &device_list, &count);
	if (ret != S_OK)
		return ret;

	for (i = 0; i < count; i++)
		bt_remove_device(device_list[i].remote_address);

	bt_free_devices(&device_list, count);

	return S_OK;
}

artik_error bt_remove_device(const char *remote_address)
{
	GVariant *result = NULL;
	GError *error = NULL;
	gchar *path = NULL;
	artik_error ret = S_OK;

	log_dbg("%s addr:%s", __func__, remote_address);

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	if (_is_connected(path))
		bt_disconnect(remote_address);

	result = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		DBUS_BLUEZ_OBJECT_PATH_HCI0,
		DBUS_IF_ADAPTER1,
		"RemoveDevice",
		g_variant_new("(o)", path),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &error);

	g_free(path);

	ret = bt_check_error(error);
	if (ret != S_OK)
		return ret;

	g_variant_unref(result);

	return S_OK;
}

artik_error bt_start_bond(const char *remote_address)
{
	GVariant *v;
	GError *e = NULL;
	gchar *path;

	if (hci.state == BT_DEVICE_STATE_PAIRING)
		return E_IN_PROGRESS;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	if (_is_paired(path)) {
		_process_connection_cb(path, BT_EVENT_BOND);
		g_free(path);
		return S_OK;
	}

	v = g_dbus_connection_call_sync(hci.conn,
			DBUS_BLUEZ_BUS,
			path,
			DBUS_IF_DEVICE1,
			"Pair",
			NULL, NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	g_free(path);

	if (e) {
		log_err(e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	hci.state = BT_DEVICE_STATE_PAIRING;

	g_variant_unref(v);

	return S_OK;
}

artik_error bt_connect(const char *remote_address)
{
	GVariant *v;
	GError *e = NULL;
	gchar *path;

	log_dbg("%s addr: %s", __func__, remote_address);

	if (hci.state == BT_DEVICE_STATE_CONNECTING)
		return E_IN_PROGRESS;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	if (hci.state == BT_DEVICE_STATE_IDLE && _is_connected(path)) {
		_process_connection_cb(path, BT_EVENT_CONNECT);
		g_free(path);
		return S_OK;
	}

	v = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		path,
		DBUS_IF_DEVICE1,
		"Connect",
		NULL, NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	g_free(path);

	if (e) {
		log_err(e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	hci.state = BT_DEVICE_STATE_CONNECTING;

	g_variant_unref(v);

	return S_OK;
}

artik_error bt_connect_profile(const char *remote_address, const char *uuid)
{
	GVariant *v;
	GError *e = NULL;
	gchar *path;

	log_dbg("%s uuid: %s", __func__, uuid);

	if (hci.state == BT_DEVICE_STATE_CONNECTING)
		return E_IN_PROGRESS;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	if (hci.state == BT_DEVICE_STATE_IDLE && _is_connected(path)) {
		_process_connection_cb(path, BT_EVENT_CONNECT);
		g_free(path);
		return S_OK;
	}

	v = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		path,
		DBUS_IF_DEVICE1,
		"ConnectProfile",
		g_variant_new("(s)", uuid),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	g_free(path);

	if (e) {
		log_err(e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	hci.state = BT_DEVICE_STATE_CONNECTING;

	g_variant_unref(v);

	return S_OK;
}

artik_error bt_disconnect(const char *remote_address)
{
	GVariant *v;
	GError *e = NULL;
	gchar *path;
	artik_error ret = S_OK;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	v = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		path,
		DBUS_IF_DEVICE1,
		"Disconnect",
		NULL, NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	g_free(path);

	if (e) {
		log_err(e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	hci.state = BT_DEVICE_STATE_IDLE;

	g_variant_unref(v);

	return ret;
}

artik_error bt_stop_bond(const char *remote_address)
{
	GVariant *v;
	GError *e = NULL;
	gchar *path;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	v = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		path,
		DBUS_IF_DEVICE1,
		"CancelPairing",
		NULL, NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	g_free(path);

	if (e) {
		log_err(e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	hci.state = BT_DEVICE_STATE_IDLE;

	g_variant_unref(v);

	return S_OK;
}

artik_error bt_set_trust(const char *remote_address)
{
	gchar *path;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	_set_trusted(path, TRUE);

	g_free(path);

	return S_OK;
}

artik_error bt_unset_trust(const char *remote_address)
{
	gchar *path;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	_set_trusted(path, FALSE);

	g_free(path);

	return S_OK;
}

artik_error bt_set_block(const char *remote_address)
{
	gchar *path;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	_set_blocked(path, TRUE);

	g_free(path);

	return S_OK;
}

artik_error bt_unset_block(const char *remote_address)
{
	gchar *path;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	_set_blocked(path, FALSE);

	g_free(path);

	return S_OK;
}

artik_error bt_get_device(const char *addr, artik_bt_device *device)
{
	GVariant *v1, *v2;
	GError *e = NULL;
	artik_error ret = S_OK;
	gchar *path = NULL;

	log_dbg("%s addr: %s", __func__, addr);

	_get_object_path(addr, &path);

	if (path == NULL)
		return E_BT_ERROR;

	v1 = g_dbus_connection_call_sync(hci.conn, DBUS_BLUEZ_BUS,
		path, DBUS_IF_PROPERTIES, "GetAll",
		g_variant_new("(s)", DBUS_IF_DEVICE1),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	g_free(path);

	ret = bt_check_error(e);
	if (ret != S_OK)
		return ret;

	g_variant_get(v1, "(@a{sv})", &v2);
	_get_device_properties(v2, device);

	g_variant_unref(v1);
	g_variant_unref(v2);

	return S_OK;
}

artik_error bt_get_devices(artik_bt_device_type device_type,
	artik_bt_device **device_list, int *count)
{
	int cnt = 0;
	artik_bt_device *tmp_list;
	artik_error ret = S_OK;

	switch (device_type) {
	case BT_DEVICE_PARIED:
		ret = _get_devices(BT_DEVICE_STATE_PAIRED, &tmp_list, &cnt);
		break;
	case BT_DEVICE_CONNECTED:
		ret = _get_devices(BT_DEVICE_STATE_CONNECTED, &tmp_list, &cnt);
		break;
	case BT_DEVICE_ALL:
		ret = _get_devices(BT_DEVICE_STATE_IDLE, &tmp_list, &cnt);
		break;
	default:
		ret = E_INVALID_VALUE;
		break;
	}
	if (ret != S_OK)
		return ret;

	*count = cnt;
	*device_list = tmp_list;

	return S_OK;
}

artik_error bt_free_device(artik_bt_device *device)
{
	return bt_free_devices(&device, 1);
}

artik_error bt_free_devices(artik_bt_device **device_list, int count)
{
	int i = 0, j = 0;

	if (*device_list == NULL)
		return S_OK;

	for (i = 0; i < count; i++) {
		for (j = 0; j < (*device_list)[i].uuid_length; j++) {
			g_free((*device_list)[i].uuid_list[j].uuid);
			g_free((*device_list)[i].uuid_list[j].uuid_name);
		}

		g_free((*device_list)[i].uuid_list);
		g_free((*device_list)[i].remote_address);
		g_free((*device_list)[i].remote_name);
		g_free((*device_list)[i].manufacturer_data);
		g_free((*device_list)[i].svc_data);
	}
	g_free(*device_list);
	*device_list = NULL;

	return S_OK;
}

bool bt_is_paired(const char *remote_address)
{
	gchar *path;
	bool paired = false;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return paired;

	paired = _is_paired(path) ? true : false;

	g_free(path);

	return paired;
}

bool bt_is_connected(const char *remote_address)
{
	gchar *path;
	bool connected = false;

	log_dbg("%s addr: %s", __func__, remote_address);

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return connected;

	connected = _is_connected(path) ? true : false;

	g_free(path);

	return connected;
}

bool bt_is_trusted(const char *remote_address)
{
	gchar *path;
	GVariant *rst = NULL;
	GVariant *v = NULL;
	GError *e = NULL;
	bool trusted = false;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	rst = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		path,
		DBUS_IF_PROPERTIES,
		"Get",
		g_variant_new("(ss)", DBUS_IF_DEVICE1, "Trusted"),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	g_free(path);

	if (e) {
		log_err(e->message);
		g_error_free(e);
		return false;
	}

	g_variant_get(rst, "(v)", &v);
	g_variant_get(v, "b", &trusted);
	g_variant_unref(rst);
	g_variant_unref(v);

	return trusted;
}

bool bt_is_blocked(const char *remote_address)
{
	gchar *path;
	GVariant *rst = NULL;
	GVariant *v = NULL;
	GError *e = NULL;
	bool blocked = false;

	_get_object_path(remote_address, &path);

	if (path == NULL)
		return E_BT_ERROR;

	rst = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		path,
		DBUS_IF_PROPERTIES,
		"Get",
		g_variant_new("(ss)", DBUS_IF_DEVICE1, "Blocked"),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	g_free(path);

	if (e) {
		log_err(e->message);
		g_error_free(e);
		return false;
	}

	g_variant_get(rst, "(v)", &v);
	g_variant_get(v, "b", &blocked);
	g_variant_unref(rst);
	g_variant_unref(v);

	return blocked;
}
