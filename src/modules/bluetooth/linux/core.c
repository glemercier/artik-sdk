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

#include <string.h>

#include "core.h"
#include "assigned_numbers.h"
#include "helper.h"
#include "device.h"
#include <inttypes.h>

bt_handler hci = {0};
bt_event_callback internal_callback[BT_EVENT_END];
char session_path[SESSION_PATH_LEN];
artik_bt_ftp_property transfer_property = {0};

static void _free_func(gpointer data)
{
	g_free(data);
}

void _set_device_class(artik_bt_class *class, uint32_t cod)
{
	class->major = (uint16_t)(cod & 0x00001F00) >> 8;
	class->minor = (uint16_t)(cod & 0x000000FC);
	class->service_class = (uint32_t)(cod & 0x00FF0000);

	if (cod & 0x002000)
		class->service_class |= BT_SERVICE_CLASS_LIMITED_DISCOVERABLE_MODE;
}

static void _hrp_callback(GVariant *v)
{
	GVariant *v0, *v1, *v2, *v3;
	guchar flags = 0, hr = 0, ee = 0, ee_val = 0, format = 0, sc_status = 0,
			ee_status = 0;
	artik_bt_hrp_data data;

	memset(&data, 0x00, sizeof(artik_bt_hrp_data));

	v0 = g_variant_get_child_value(v, 0);
	v1 = g_variant_get_child_value(v, 1);
	v2 = g_variant_get_child_value(v, 2);
	v3 = g_variant_get_child_value(v, 3);

	g_variant_get(v0, "y", &flags);
	g_variant_get(v1, "y", &hr);
	g_variant_get(v2, "y", &ee);
	g_variant_get(v3, "y", &ee_val);

	g_variant_unref(v0);
	g_variant_unref(v1);
	g_variant_unref(v2);
	g_variant_unref(v3);

	format = flags & 0x01;
	sc_status = (flags >> 1) & 0x03;
	ee_status = flags & 0x08;
	log_dbg("flags: 0x%02x, format: 0x%02x, sc_st: 0x%02x, ee_st: 0x%02x",
			flags, format, sc_status, ee_status);

	if (format != 0x00)
		hr = hr | (ee << 8);

	if (ee_status) {
		log_dbg("energy extended : %d", ee_val);
		data.energy = ee_val;
	}

	log_dbg("heart rate: %d", hr);

	data.bpm = hr;
	if (sc_status == 3)
		data.contact = true;
	else
		data.contact = false;

	_user_callback(BT_EVENT_PF_HEARTRATE, &data);
}

static void _on_gatt_data_received(GVariant *properties, gchar *srv_uuid, gchar *char_uuid)
{
	GVariant *prop = NULL, *v = NULL, *v1 = NULL;
	gchar *key = NULL;
	guint i = 0, len = 0;
	artik_bt_gatt_data data;

	log_dbg("%s [%s]", __func__, char_uuid);

	memset(&data, 0x00, sizeof(artik_bt_gatt_data));

	prop = g_variant_get_child_value(properties, 0);
	g_variant_get(prop, "{&sv}", &key, &v);
	if (g_strcmp0(key, "Value") != 0) {
		g_variant_unref(prop);
		g_variant_unref(v);
		return;
	}

	len = g_variant_n_children(v);

	data.srv_uuid = srv_uuid;
	data.char_uuid = char_uuid;
	data.length = len;
	data.bytes = (unsigned char *)malloc(sizeof(unsigned char) * len);

	for (i = 0; i < len; i++) {
		v1 = g_variant_get_child_value(v, i);
		data.bytes[i] = g_variant_get_byte(v1);
		g_variant_unref(v1);
	}

	_user_callback(BT_EVENT_GATT_CHARACTERISTIC, &data);

	g_variant_unref(prop);
	g_variant_unref(v);
	g_free(data.bytes);
}

static void _on_hrp_measurement_received(GVariant *properties)
{
	GVariant *v;
	GVariantIter *iter;
	gchar *key;

	log_dbg("%s", __func__);

	g_variant_get(properties, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{&sv}", &key, &v)) {
		if (g_strcmp0(key, "Value") == 0) {
			if (g_variant_n_children(v) < 4) {
				log_err("invalid HRP data");
				g_variant_unref(v);
				break;
			}

			_hrp_callback(v);
		}
	}
	g_variant_iter_free(iter);
}

void _user_callback(artik_bt_event event, void *data)
{
	log_dbg("%s [%d]", __func__, event);

	if ((event < 0) || (event >= BT_EVENT_END))
		return;

	if (hci.callback[event].fn == NULL)
		return;

	hci.callback[event].fn(event, data, hci.callback[event].user_data);
}

static void _device_properties_changed(const gchar *path, GVariant *properties)
{
	GVariant *val;
	GVariantIter *iter;
	gchar *key;

	g_variant_get(properties, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{&sv}", &key, &val)) {

		log_dbg("%s key: %s, state: %d", __func__, key, hci.state);

		if (g_strcmp0(key, "Connected") == 0) {

			if (hci.state == BT_DEVICE_STATE_IDLE
					|| hci.state == BT_DEVICE_STATE_CONNECTING)
				_process_connection_cb(path, BT_EVENT_CONNECT);
			else if (hci.state == BT_DEVICE_STATE_PAIRING
					&& !g_variant_get_boolean(val))
				_process_connection_cb(path, BT_EVENT_BOND);

		} else if (g_strcmp0(key, "Paired") == 0) {

			if (hci.state == BT_DEVICE_STATE_IDLE)
				_process_connection_cb(path, BT_EVENT_BOND);

		} else if (g_strcmp0(key, "ServicesResolved") == 0) {

			if (hci.state == BT_DEVICE_STATE_IDLE && g_variant_get_boolean(val))
				_process_service_cb(path, BT_EVENT_SERVICE_RESOLVED);
		}
	}

	g_variant_iter_free(iter);
}

static void _proximity_properties_changed(GVariant *variant)
{
	GVariant *key_variant, *val_variant;

	artik_bt_gatt_data bt_pxp_data;

	key_variant = g_variant_get_child_value(variant, 0);
	val_variant = g_variant_get_child_value(key_variant, 1);
	g_variant_get(g_variant_get_child_value(key_variant, 0), "s",
			&(bt_pxp_data.key));
	g_variant_get(g_variant_get_child_value(val_variant, 0), "s",
			&(bt_pxp_data.value));

	_user_callback(BT_EVENT_PROXIMITY, &(bt_pxp_data));

	g_variant_unref(key_variant);
	g_variant_unref(val_variant);
}

static void _obex_properties_changed(const char *object_path,
		GVariant *properties)
{
	if (transfer_property.object_path == NULL)
		return;

	if (g_strcmp0(object_path, transfer_property.object_path))
		return;

	_fill_transfer_property(properties);

	internal_callback[BT_EVENT_FTP].fn(BT_EVENT_FTP, &transfer_property, NULL);
}

static void _pan_properties_changed(const gchar *path, GVariant *properties)
{
	GVariant *val;
	GVariantIter *iter;
	gchar *key;

	g_variant_get(properties, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{&sv}", &key, &val)) {
		if (g_strcmp0(key, "Connected") == 0) {

			_process_connection_cb(path, BT_EVENT_CONNECT);

			g_variant_unref(val);
			break;
		}
	}
	g_variant_iter_free(iter);
}

void _get_adapter_properties(GVariant *prop_array, artik_bt_adapter *adapter)
{
	GVariant *v, *uuid;
	GVariantIter *iter;
	gchar *key = NULL;
	gint i = 0, uuid_len = 0;
	uint32_t cod;

	if (!adapter)
		return;

	memset(adapter, 0x00, sizeof(artik_bt_adapter));

	g_variant_get(prop_array, "(a{sv})", &iter);
	while (g_variant_iter_loop(iter, "{&sv}", &key, &v)) {
		if (g_strcmp0(key, "Address") == 0) {
			g_variant_get(v, "s", &adapter->address);
		} else if (g_strcmp0(key, "Name") == 0) {
			g_variant_get(v, "s", &adapter->name);
		} else if (g_strcmp0(key, "Alias") == 0) {
			g_variant_get(v, "s", &adapter->alias);
		} else if (g_strcmp0(key, "Class") == 0) {
			g_variant_get(v, "u", &cod);
			_set_device_class(&adapter->cod, cod);
		} else if (g_strcmp0(key, "Discoverable") == 0) {
			g_variant_get(v, "b", &adapter->discoverable);
		} else if (g_strcmp0(key, "Discovering") == 0) {
			g_variant_get(v, "b", &adapter->discovering);
		} else if (g_strcmp0(key, "Pairable") == 0) {
			g_variant_get(v, "b", &adapter->pairable);
		} else if (g_strcmp0(key, "PairableTimeout") == 0) {
			g_variant_get(v, "u", &adapter->pair_timeout);
		} else if (g_strcmp0(key, "DiscoverableTimeout") == 0) {
			g_variant_get(v, "u", &adapter->discover_timeout);
		} else if (g_strcmp0(key, "UUIDs") == 0) {

			uuid_len = g_variant_n_children(v);
			adapter->uuid_length = uuid_len;

			if (uuid_len > 0) {
				adapter->uuid_list = g_try_new0(artik_bt_uuid, uuid_len);
				if (!adapter->uuid_list) {
					g_variant_unref(v);
					break;
				}

				for (i = 0; i < uuid_len; i++) {
					uuid = g_variant_get_child_value(v, i);

					g_variant_get(uuid, "s", &adapter->uuid_list[i].uuid);
					adapter->uuid_list[i].uuid_name
						= g_strdup(_get_uuid_name(adapter->uuid_list[i].uuid));

					g_variant_unref(uuid);
				}
			}
		}
	}
	g_variant_iter_free(iter);
}

void _get_device_properties(GVariant *prop_array, artik_bt_device *device)
{
	GVariant *v, *uuid, *v_mfr, *v_mfr_data, *v_byte, *v_svc, *v_svc_data;
	GVariantIter *iter;
	gchar *key = NULL, *svc_uuid = NULL;
	gint i = 0, uuid_len = 0;
	guint32 cod;
	guint16 mfr_id = 0;

	if (!device)
		return;
	memset(device, 0x00, sizeof(artik_bt_device));

	g_variant_get(prop_array, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{&sv}", &key, &v)) {
		if (g_strcmp0(key, "Address") == 0) {
			g_variant_get(v, "s", &device->remote_address);
		} else if (g_strcmp0(key, "Name") == 0) {
			g_variant_get(v, "s", &device->remote_name);
		} else if (g_strcmp0(key, "Class") == 0) {
			g_variant_get(v, "u", &cod);
			_set_device_class(&device->cod, cod);
		} else if (g_strcmp0(key, "RSSI") == 0) {
			g_variant_get(v, "n", &device->rssi);
		} else if (g_strcmp0(key, "Paired") == 0) {
			g_variant_get(v, "b", &device->is_bonded);
		} else if (g_strcmp0(key, "Connected") == 0) {
			g_variant_get(v, "b", &device->is_connected);
		} else if (g_strcmp0(key, "UUIDs") == 0) {
			uuid_len = g_variant_n_children(v);
			device->uuid_length = uuid_len;
			if (uuid_len > 0) {
				device->uuid_list
					= (artik_bt_uuid *)malloc(sizeof(artik_bt_uuid) * uuid_len);
				for (i = 0; i < uuid_len; i++) {
					uuid = g_variant_get_child_value(v, i);

					g_variant_get(uuid, "s", &device->uuid_list[i].uuid);
					device->uuid_list[i].uuid_name
						= g_strdup(_get_uuid_name(device->uuid_list[i].uuid));

					g_variant_unref(uuid);
				}
			}
		} else if (g_strcmp0(key, "ManufacturerData") == 0) {
			v_mfr = g_variant_get_child_value(v, 0);
			g_variant_get(v_mfr, "{qv}", &mfr_id, &v_mfr_data);

			device->manufacturer_id = mfr_id;
			strncpy(device->manufacturer_name, _get_company_name(mfr_id),
					MAX_BT_NAME_LEN);

			device->manufacturer_data_len = g_variant_n_children(v_mfr_data);
			if (device->manufacturer_data_len > 0) {
				device->manufacturer_data
						= (char *)malloc(device->manufacturer_data_len);
				for (i = 0; i < device->manufacturer_data_len; i++) {
					v_byte = g_variant_get_child_value(v_mfr_data, i);
					g_variant_get(v_byte, "y", &device->manufacturer_data[i]);
					g_variant_unref(v_byte);
				}
			}
			g_variant_unref(v_mfr);
			g_variant_unref(v_mfr_data);
		} else if (g_strcmp0(key, "ServiceData") == 0) {
			v_svc = g_variant_get_child_value(v, 0);
			g_variant_get(v_svc, "{&sv}", &svc_uuid, &v_svc_data);

			strncpy(device->svc_uuid, svc_uuid, MAX_BT_UUID_LEN);

			device->svc_data_len = g_variant_n_children(v_svc_data);
			if (device->svc_data_len > 0) {
				device->svc_data = (char *)malloc(device->svc_data_len);
				for (i = 0; i < device->svc_data_len; i++) {
					v_byte = g_variant_get_child_value(v_svc_data, i);
					g_variant_get(v_byte, "y", &device->svc_data[i]);
					g_variant_unref(v_byte);
				}
			}
			g_variant_unref(v_svc);
			g_variant_unref(v_svc_data);
		}
	}
	g_variant_iter_free(iter);
}

artik_error _get_managed_objects(GVariant **variant)
{
	GError *e = NULL;

	*variant = g_dbus_connection_call_sync(hci.conn,
			DBUS_BLUEZ_BUS, "/", DBUS_IF_OBJECT_MANAGER,
			"GetManagedObjects",
			NULL, NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	return bt_check_error(e);
}

void _get_object_path(const char *addr, char **path)
{
	GVariant *obj1, *ar1, *ar2, *v;
	GVariantIter *iter1, *iter2, *iter3;
	gchar *obj_path, *itf, *key;
	const gchar *value;

	*path = NULL;

	if (_get_managed_objects(&obj1) != S_OK)
		return;

	g_variant_get(obj1, "(a{oa{sa{sv}}})", &iter1);
	while (g_variant_iter_loop(iter1, "{&o@a{sa{sv}}}", &obj_path, &ar1)) {

		g_variant_get(ar1, "a{sa{sv}}", &iter2);
		while (g_variant_iter_loop(iter2, "{&s@a{sv}}", &itf, &ar2)) {

			if (strcasecmp(itf, DBUS_IF_DEVICE1) != 0)
				continue;

			g_variant_get(ar2, "a{sv}", &iter3);
			while (g_variant_iter_loop(iter3, "{&sv}", &key, &v)) {

				if (g_strcmp0(key, "Address") == 0) {
					value = g_variant_get_string(v, NULL);

					if (strcasecmp(value, addr) == 0)
						*path = g_strdup(obj_path);
				}
			}
			g_variant_iter_free(iter3);
		}
		g_variant_iter_free(iter2);
	}
	g_variant_iter_free(iter1);

	g_variant_unref(obj1);
}

artik_error _get_devices(bt_device_state state,
		artik_bt_device **device_list, int *count)
{
	GVariant *objects, *if_array, *prop_array;
	GVariantIter *iter1, *iter2;
	gchar *path, *itf;
	gint cnt = 0;
	artik_bt_device *tmp_list = NULL;
	artik_error ret = S_OK;

	log_dbg("%s state:%d", __func__, state);

	ret = _get_managed_objects(&objects);
	if (ret != S_OK)
		return ret;

	g_variant_get(objects, "(a{oa{sa{sv}}})", &iter1);
	while (g_variant_iter_loop(iter1, "{&o@a{sa{sv}}}", &path, &if_array)) {

		g_variant_get(if_array, "a{sa{sv}}", &iter2);
		while (g_variant_iter_loop(iter2, "{&s@a{sv}}", &itf, &prop_array)) {

			if (strcasecmp(itf, DBUS_IF_DEVICE1) != 0)
				continue;

			switch (state) {
			case BT_DEVICE_STATE_IDLE:
				cnt++;
				tmp_list = (artik_bt_device *)realloc(tmp_list,
						sizeof(artik_bt_device) * cnt);
				if (!tmp_list) {
					g_variant_unref(objects);
					g_variant_unref(prop_array);
					g_variant_unref(if_array);
					g_variant_iter_free(iter2);
					g_variant_iter_free(iter1);
					return E_NO_MEM;
				}
				_get_device_properties(prop_array, &tmp_list[cnt-1]);
				break;
			case BT_DEVICE_STATE_PAIRED:
				if (_is_paired(path)) {
					cnt++;
					tmp_list = (artik_bt_device *)realloc(tmp_list,
							sizeof(artik_bt_device) * cnt);
					if (!tmp_list) {
						g_variant_unref(objects);
						g_variant_unref(prop_array);
						g_variant_unref(if_array);
						g_variant_iter_free(iter2);
						g_variant_iter_free(iter1);
						return E_NO_MEM;
					}
					_get_device_properties(prop_array, &tmp_list[cnt-1]);
				}
				break;
			case BT_DEVICE_STATE_CONNECTED:
				if (_is_connected(path)) {
					cnt++;
					tmp_list = (artik_bt_device *)realloc(tmp_list,
							sizeof(artik_bt_device) * cnt);
					if (!tmp_list) {
						g_variant_unref(objects);
						g_variant_unref(prop_array);
						g_variant_unref(if_array);
						g_variant_iter_free(iter2);
						g_variant_iter_free(iter1);
						return E_NO_MEM;
					}
					_get_device_properties(prop_array, &tmp_list[cnt-1]);
				}
				break;
			default:
				log_dbg("state %d is not supported", state);
				break;
			}
		}
		g_variant_iter_free(iter2);
	}

	*count = cnt;
	*device_list = tmp_list;

	g_variant_iter_free(iter1);
	g_variant_unref(objects);

	return ret;
}

void _get_gatt_path(const char *addr, const char *interface, const char *uuid,
		const char *property, const char *value, gchar **gatt_path)
{
	GVariant *obj1, *ar1, *ar2, *val;
	GVariantIter *iter1, *iter2, *iter3;
	gchar *path, *dev_path, *itf, *key;

	*gatt_path = NULL;

	_get_object_path(addr, &dev_path);
	if (dev_path == NULL)
		return;

	if (_get_managed_objects(&obj1) != S_OK)
		return;

	g_variant_get(obj1, "(a{oa{sa{sv}}})", &iter1);
	while (g_variant_iter_loop(iter1, "{&o@a{sa{sv}}}", &path, &ar1)) {
		if (*gatt_path != NULL) {
			g_variant_unref(ar1);
			break;
		}

		if (!g_str_has_prefix(path, dev_path))
			continue;

		g_variant_get(ar1, "a{sa{sv}}", &iter2);
		while (g_variant_iter_loop(iter2, "{&s@a{sv}}", &itf, &ar2)) {

			if (*gatt_path != NULL) {
				g_variant_unref(ar2);
				break;
			}

			if (g_strcmp0(itf, interface) != 0)
				continue;

			bool is_good_uuid = false;
			bool is_good_property = false;

			if (property == NULL)
				is_good_property = true;

			g_variant_get(ar2, "a{sv}", &iter3);
			while (g_variant_iter_loop(iter3, "{&sv}", &key, &val)) {
				if (!g_strcmp0(key, "UUID")) {
					const gchar *id = g_variant_get_string(val, NULL);

					if (!g_strcmp0(uuid, id))
						is_good_uuid = true;
				}

				if (!g_strcmp0(key, property)) {
					const gchar *str_val = g_variant_get_string(val, NULL);

					if (!g_strcmp0(value, str_val))
						is_good_property = true;
				}

				if (is_good_property && is_good_uuid) {
					*gatt_path = strdup(path);
					g_variant_unref(val);
					break;
				}
			}
			g_variant_iter_free(iter3);
		}
		g_variant_iter_free(iter2);
	}
	g_variant_iter_free(iter1);
	g_variant_unref(obj1);
	g_free(dev_path);
}

void _get_gatt_uuid_list(const char *gatt_path, const char *interface,
		artik_bt_uuid **uuid_list, int *len)
{
	GVariant *obj1, *ar1, *ar2, *val;
	GVariantIter *iter1, *iter2, *iter3;
	gchar *path, *itf, *key;
	const gchar *uuid;
	artik_bt_uuid *uuids;
	GSList *srv_list = NULL;
	guint uuid_len = 0;
	unsigned int i = 0;

	*uuid_list = NULL;
	*len = 0;

	if (_get_managed_objects(&obj1) != S_OK)
		return;

	g_variant_get(obj1, "(a{oa{sa{sv}}})", &iter1);
	while (g_variant_iter_loop(iter1, "{&o@a{sa{sv}}}", &path, &ar1)) {
		if (!g_str_has_prefix(path, gatt_path))
			continue;

		g_variant_get(ar1, "a{sa{sv}}", &iter2);
		while (g_variant_iter_loop(iter2, "{&s@a{sv}}", &itf, &ar2)) {
			if (g_strcmp0(itf, interface) != 0)
				continue;

			g_variant_get(ar2, "a{sv}", &iter3);
			while (g_variant_iter_loop(iter3, "{&sv}", &key, &val)) {
				if (g_strcmp0(key, "UUID") != 0)
					continue;

				uuid = g_variant_get_string(val, NULL);
				srv_list = g_slist_append(srv_list, strdup(uuid));
			}
			g_variant_iter_free(iter3);
		}
		g_variant_iter_free(iter2);
	}
	g_variant_iter_free(iter1);

	uuid_len = g_slist_length(srv_list);
	uuids = (artik_bt_uuid *)malloc(sizeof(artik_bt_uuid) * uuid_len);

	for (i = 0; i < uuid_len; i++) {
		uuids[i].uuid = g_strdup(g_slist_nth_data(srv_list, i));
		uuids[i].uuid_name = g_strdup(_get_uuid_name(uuids[i].uuid));
	}

	*len = uuid_len;
	*uuid_list = uuids;

	g_slist_free_full(srv_list, _free_func);
	g_variant_unref(obj1);
}

static artik_error _get_all_device_properties(const gchar *path, GVariant **v)
{
	GError *e = NULL;

	log_dbg("%s %s", __func__, path);

	*v = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		path,
		DBUS_IF_PROPERTIES,
		"GetAll",
		g_variant_new("(s)", DBUS_IF_DEVICE1),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &e);

	return bt_check_error(e);
}

static void _process_gatt_service(gchar *path)
{
	/* TODO: process gatt service here */
}

void _process_connection_cb(const gchar *path, artik_bt_event e)
{
	GVariant *v1, *v2;
	artik_bt_device *device;

	log_dbg("%s %s, evt: %d", __func__, path, e);

	if (!(e & (BT_EVENT_BOND | BT_EVENT_CONNECT)))
		return;

	device = g_try_new0(artik_bt_device, 1);
	if (!device)
		return;
	memset(device, 0, sizeof(artik_bt_device));

	hci.state = BT_DEVICE_STATE_IDLE;

	if (_get_all_device_properties(path, &v1) == S_OK) {

		v2 = g_variant_get_child_value(v1, 0);
		_get_device_properties(v2, device);

		g_variant_unref(v1);
		g_variant_unref(v2);
	}

	_user_callback(e, device);

	bt_free_device(device);
}

void _process_service_cb(const gchar *path, artik_bt_event e)
{
	GVariant *v1, *v2;
	artik_bt_device *device;

	log_dbg("%s %s, evt: %d", __func__, path, e);

	if (!(e & BT_EVENT_SERVICE_RESOLVED))
		return;

	if (_get_all_device_properties(path, &v1) == S_OK) {

		device = g_try_new0(artik_bt_device, 1);
		if (!device) {
			g_variant_unref(v1);
			return;
		}
		memset(device, 0, sizeof(artik_bt_device));

		v2 = g_variant_get_child_value(v1, 0);
		_get_device_properties(v2, device);

		_user_callback(e, device);

		bt_free_device(device);

		g_variant_unref(v1);
		g_variant_unref(v2);
	}
}

static void _gatt_properties_changed(const gchar *object_path,
		GVariant *properties)
{
	GVariant *r, *v;
	guint i = 0, len = 0;
	bt_gatt_client *client;

	log_dbg("%s path: %s", __func__, object_path);

	r = g_dbus_connection_call_sync(
		hci.conn,
		DBUS_BLUEZ_BUS,
		object_path,
		DBUS_IF_PROPERTIES,
		"Get",
		g_variant_new("(ss)", DBUS_IF_GATTCHARACTERISTIC1, "UUID"),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, NULL);

	g_variant_get(r, "(v)", &v);
	if (g_strcmp0(g_variant_get_string(v, NULL),
			UUID_HEART_RATE_MEASUREMENT) == 0)
		_on_hrp_measurement_received(properties);
	else {
		len = g_slist_length(hci.gatt_clients);
		for (i = 0; i < len; i++) {
			client =  g_slist_nth_data(hci.gatt_clients, i);
			if (g_strcmp0(object_path, client->path) == 0) {
				_on_gatt_data_received(properties, client->srv_uuid,
						client->char_uuid);
				break;
			}
		}
	}

	g_variant_unref(r);
	g_variant_unref(v);
}

void _on_interface_added(const gchar *sender_name,
	const gchar *object_path, const gchar *interface_name,
	GVariant *parameters, gpointer user_data)
{
	GVariantIter *iter;
	GVariant *device_array, *prop_array;
	gchar *path = NULL;
	gchar *interface = NULL;
	artik_bt_device *device = NULL;

	g_variant_get(parameters, "(&o@a{sa{sv}})", &path, &device_array);
	log_dbg("InterfacesAdded [%s]", path);

	g_variant_get(device_array, "a{sa{sv}}", &iter);
	while (g_variant_iter_loop(iter, "{&s@a{sv}}", &interface, &prop_array)) {
		if (g_strcmp0(interface, DBUS_IF_DEVICE1) == 0) {
			device = (artik_bt_device *)malloc(sizeof(artik_bt_device));
			_get_device_properties(prop_array, device);
			_user_callback(BT_EVENT_SCAN, device);
			bt_free_device(device);
		} else if (g_strcmp0(interface, DBUS_IF_GATTSERVICE1) == 0) {

			_process_gatt_service(path);

		} else if (g_strcmp0(interface, DBUS_IF_OBEX_TRANSFER) == 0) {
			if (transfer_property.object_path != NULL)
				free(transfer_property.object_path);
			transfer_property.object_path = (char *) malloc(strlen(path) + 1);
			strncpy(transfer_property.object_path, path, strlen(path));
			transfer_property.object_path[strlen(path)] = '\0';

			if (transfer_property.file_name != NULL) {
				free(transfer_property.file_name);
				transfer_property.file_name = NULL;
			}

			if (transfer_property.name != NULL) {
				free(transfer_property.name);
				transfer_property.name = NULL;
			}

			if (transfer_property.status != NULL) {
				free(transfer_property.status);
				transfer_property.status = NULL;
			}
			transfer_property.transfered = 0;
			transfer_property.size = 0;
			_fill_transfer_property(prop_array);
		}
	}
	g_variant_iter_free(iter);
	g_variant_unref(device_array);
}

void _on_interface_removed(const gchar *sender_name,
	const gchar *object_path, const gchar *interface_name,
	GVariant *parameters, gpointer user_data)
{
	GVariantIter *iter;
	gchar *path = NULL, *interface = NULL;

	g_variant_get(parameters, "(&oas)", &path, &iter);
	log_dbg("%s [%s]", __func__, path);

	while (g_variant_iter_loop(iter, "&s", &interface)) {
		if (g_strcmp0(interface, DBUS_IF_OBEX_SESSION) == 0) {
			memset(session_path, 0, SESSION_PATH_LEN);

		} else if (g_strcmp0(interface, DBUS_IF_OBEX_TRANSFER) == 0) {

			g_free(transfer_property.object_path);
			transfer_property.object_path = NULL;

			g_free(transfer_property.file_name);
			transfer_property.file_name = NULL;

			g_free(transfer_property.name);
			transfer_property.name = NULL;

			g_free(transfer_property.status);
			transfer_property.status = NULL;

			transfer_property.transfered = 0;
			transfer_property.size = 0;
		}
	}
	g_variant_iter_free(iter);
}

void _on_properties_changed(const gchar *sender_name,
	const gchar *object_path, const gchar *interface_name,
	GVariant *parameters, gpointer user_data)
{
	GVariant *properties;
	gchar *interface;

	g_variant_get(parameters, "(&s@a{sv}@as)", &interface, &properties, NULL);

	if (g_str_has_prefix(object_path, DBUS_BLUEZ_OBJECT_PATH)) {
		log_dbg("%s %s %s", __func__, object_path, interface_name);
		print_variant(parameters);

		if (g_strcmp0(DBUS_IF_DEVICE1, interface) == 0) {
			_device_properties_changed(object_path, properties);

		} else if (g_strcmp0(DBUS_IF_PROXIMITYREPORTER1, interface) == 0 ||
				g_strcmp0(DBUS_IF_PROXIMITYMONITOR1, interface) == 0) {
			_proximity_properties_changed(properties);

		} else if (g_strcmp0(DBUS_IF_GATTCHARACTERISTIC1, interface) == 0) {
			_gatt_properties_changed(object_path, properties);

		} else if (g_strcmp0(DBUS_IF_OBEX_TRANSFER, interface) == 0) {
			_obex_properties_changed(object_path, properties);

		} else if (g_strcmp0(DBUS_IF_NETWORK1, interface) == 0) {
			_pan_properties_changed(object_path, properties);
		}
	} else if (g_str_has_prefix(object_path, GATT_SERVICE_PREFIX)) {
		log_dbg("%s %s %s", __func__, object_path, interface_name);
		print_variant(parameters);

		if (g_strcmp0(DBUS_IF_GATTCHARACTERISTIC1, interface) == 0) {
			/* TODO: We can pass on changed properties to the higher layer */
			;
		}
	}

	g_variant_unref(properties);
}

void _dbus_signal_callback(GDBusConnection *conn,
	const gchar *sender_name, const gchar *object_path,
	const gchar *interface_name, const gchar *signal_name,
	GVariant *parameters, gpointer user_data)
{
	if (g_strcmp0(signal_name, "InterfacesAdded") == 0) {
		_on_interface_added(sender_name, object_path, interface_name,
			parameters, user_data);
	} else if (g_strcmp0(signal_name, "PropertiesChanged") == 0) {
		_on_properties_changed(sender_name, object_path, interface_name,
			parameters, user_data);
	} else if (g_strcmp0(signal_name, "InterfacesRemoved") == 0) {
		_on_interface_removed(sender_name, object_path, interface_name,
			parameters, user_data);
	}
}

gboolean _is_connected(const char *device_path)
{
	GVariant *rst = NULL;
	GVariant *v = NULL;
	gboolean b = FALSE;
	GError *error = NULL;

	rst = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		device_path,
		DBUS_IF_PROPERTIES,
		"Get",
		g_variant_new("(ss)", DBUS_IF_DEVICE1, "Connected"),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &error);

	if (bt_check_error(error) != S_OK)
		return b;

	g_variant_get(rst, "(v)", &v);
	g_variant_get(v, "b", &b);
	g_variant_unref(rst);
	g_variant_unref(v);

	return b;
}

gboolean _is_paired(const char *device_path)
{
	GVariant *rst = NULL;
	GVariant *v = NULL;
	gboolean b = FALSE;
	GError *error = NULL;

	rst = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		device_path,
		DBUS_IF_PROPERTIES,
		"Get",
		g_variant_new("(ss)", DBUS_IF_DEVICE1, "Paired"),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &error);

	if (bt_check_error(error) != S_OK)
		return b;

	g_variant_get(rst, "(v)", &v);
	g_variant_get(v, "b", &b);
	g_variant_unref(rst);
	g_variant_unref(v);

	return b;
}

void _fill_transfer_property(GVariant *dict)
{
	GVariantIter *iter = NULL;
	gchar *key = NULL;
	GVariant *val = NULL;

	g_variant_get(dict, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{&sv}", &key, &val))
	{
		if (g_strcmp0(key, "Filename") == 0) {
			if (transfer_property.file_name != NULL)
				g_free(transfer_property.file_name);

			g_variant_get(val, "s", &transfer_property.file_name);

		} else if (g_strcmp0(key, "Name") == 0) {
			if (transfer_property.name != NULL)
				g_free(transfer_property.name);

			g_variant_get(val, "s", &transfer_property.name);

		} else if (g_strcmp0(key, "Status") == 0) {
			if (transfer_property.status != NULL)
				g_free(transfer_property.status);

			g_variant_get(val, "s", &transfer_property.status);
		} else if (g_strcmp0(key, "Transferred") == 0) {
			g_variant_get(val, "t", &transfer_property.transfered);

		} else if (g_strcmp0(key, "Size") == 0) {
			g_variant_get(val, "t", &transfer_property.size);
		}
	}

	g_variant_iter_free(iter);
}

artik_error bt_check_error(GError *err)
{
	if (!err)
		return S_OK;

	/* Check for "Unit dbus-org.bluez.service not found" error */
	if (g_error_matches(err, g_quark_from_static_string("g-io-error-quark"), 36)) {
		log_dbg(err->message);
		return E_BUSY;
	}

	log_dbg(err->message);
	g_error_free(err);

	return E_BT_ERROR;
}

void _get_device_address(const gchar *path, gchar **address)
{
	GVariant *tuple, *v;

	tuple = g_dbus_connection_call_sync(hci.conn,
		DBUS_BLUEZ_BUS,
		path,
		DBUS_IF_PROPERTIES,
		"Get",
		g_variant_new("(ss)", DBUS_IF_DEVICE1, "Address"),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, NULL);

	g_variant_get(tuple, "(v)", &v);
	g_variant_get(v, "s", address);

	g_variant_unref(tuple);
	g_variant_unref(v);
}
