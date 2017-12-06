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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <gio/gio.h>
#pragma GCC diagnostic pop
#include <string.h>
#include <stdlib.h>
#include "core.h"
#include "gatt.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"

static GDBusNodeInfo *service_node_info;
static GDBusNodeInfo *characteristic_node_info;
static GDBusNodeInfo *descriptor_node_info;

static const gchar service_introspection_xml[] =
"<node name='/'>"
"\t<interface name='org.freedesktop.DBus.ObjectManager'>"
"\t\t<method name='GetManagedObjects'>"
"\t\t\t<arg type='a{oa{sa{sv}}}' name='Objects' direction='out'/>"
"\t\t</method>"
"\t</interface>"
"\t<interface name='org.bluez.GattService1'>"
"\t\t<property type='s' name='UUID' access='read'>"
"\t\t</property>"
"\t\t<property type='b' name='primary' access='read'>"
"\t\t</property>"
"\t\t<property type='o' name='Device' access='read'>"
"\t\t</property>"
"\t\t<property type='ao' name='Characteristics' access='read'>"
"\t\t</property>"
"\t\t<property type='s' name='Includes' access='read'>"
"\t\t</property>"
"\t</interface>"
"</node>";

static const gchar char_introspection_xml[] =
"<node name='/'>"
"\t<interface name='org.bluez.GattCharacteristic1'>"
"\t\t<method name='ReadValue'>"
"\t\t\t<arg type='a{sv}' name='options' direction='in'/>"
"\t\t<arg type='ay' name='Value' direction='out'/>"
"\t\t</method>"
"\t\t<method name='WriteValue'>"
"\t\t\t<arg type='ay' name='value' direction='in'/>"
"\t\t\t<arg type='a{sv}' name='options' direction='in'/>"
"\t\t</method>"
"\t\t<method name='StartNotify'>"
"\t\t</method>"
"\t\t<method name='StopNotify'>"
"\t\t</method>"
"\t\t<method name='IndicateConfirm'>"
"\t\t\t<arg type='s' name='address' direction='in'/>"
"\t\t\t<arg type='b' name='complete' direction='in'/>"
"\t\t</method>"
"\t</interface>"
"\t<interface name='org.freedesktop.DBus.Properties'>"
"\t\t<property type='s' name='UUID' access='read'>"
"\t\t</property>"
"\t\t<property type='o' name='Service' access='read'>"
"\t\t</property>"
"\t\t<property type='ay' name='Value' access='readwrite'>"
"\t\t</property>"
"\t\t<property type='b' name='Notifying' access='read'>"
"\t\t</property>"
"\t\t<property type='as' name='Flags' access='read'>"
"\t\t</property>"
"\t\t<property type='s' name='Unicast' access='read'>"
"\t\t</property>"
"\t\t<property type='ao' name='Descriptors' access='read'>"
"\t\t</property>"
"\t</interface>"
"</node>";

static const gchar descriptor_introspection_xml[] =
"<node name='/'>"
"\t<interface name='org.bluez.GattDescriptor1'>"
"\t\t<method name='ReadValue'>"
"\t\t\t<arg type='a{sv}' name='options' direction='in'/>"
"\t\t\t<arg type='ay' name='Value' direction='out'/>"
"\t\t</method>"
"\t\t<method name='WriteValue'>"
"\t\t\t<arg type='ay' name='value' direction='in'/>"
"\t\t\t<arg type='a{sv}' name='options' direction='in'/>"
"\t\t</method>"
"\t</interface>"
"\t<interface name='org.freedesktop.DBus.Properties'>"
"\t\t<property type='s' name='UUID' access='read'>"
"\t\t</property>"
"\t\t<property type='o' name='Characteristic' access='read'>"
"\t\t</property>"
"\t\t<property type='ay' name='Value' access='read'>"
"\t\t</property>"
"\t\t<property type='as' name='Flags' access='read'>"
"\t\t</property>"
"\t\t<property type='s' name='Permissions' access='read'>"
"\t\t</property>"
"\t</interface>"
"</node>";
#pragma GCC diagnostic pop

static void _serv_method_call(GDBusConnection * connection, const gchar *sender,
		const gchar *object_path, const gchar *interface_name,
		const gchar *method_name, GVariant * parameters,
		GDBusMethodInvocation * invocation, gpointer user_data)
{
	GVariantBuilder *b, *b_svc, *b_svc1, *b_svc11;
	GVariantBuilder *b_char, *b_char1, *b_char11, *b_char12, *b_char13;
	GVariantBuilder *b_desc, *b_desc1, *b_desc11, *b_desc12;
	GSList *l1, *l2;
	gboolean notify = FALSE;
	guint i;
	gchar *unicast = "00:00:00:00:00:00";
	bt_gatt_service *serv_info = user_data;
	bt_gatt_char *char_info;
	bt_gatt_desc *desc_info;

	if (g_strcmp0(method_name, "GetManagedObjects") == 0) {
		log_dbg("getting values for service, chars and descriptors");

		if (!g_str_has_prefix(object_path, GATT_SERVICE_PREFIX))
			g_dbus_method_invocation_return_value(invocation, NULL);

		b = g_variant_builder_new(G_VARIANT_TYPE("a{oa{sa{sv}}}"));
		b_svc = g_variant_builder_new(G_VARIANT_TYPE("a{sa{sv}}"));
		b_svc1 = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
		b_svc11 = g_variant_builder_new(G_VARIANT_TYPE("ao"));

		g_variant_builder_add(b_svc1, "{sv}", "UUID",
				g_variant_new_string(serv_info->service_uuid));
		g_variant_builder_add(b_svc1, "{sv}", "Primary",
				g_variant_new_boolean(serv_info->is_svc_primary));

		for (l1 = serv_info->char_data; l1 != NULL; l1 = l1->next) {
			char_info = l1->data;
			g_variant_builder_add(b_svc11, "o", char_info->char_path);
		}
		g_variant_builder_add(b_svc1, "{sv}", "Characteristics",
				g_variant_new("ao", b_svc11));
		g_variant_builder_add(b_svc, "{sa{sv}}",
				DBUS_IF_GATTSERVICE1, b_svc1);
		g_variant_builder_add(b, "{oa{sa{sv}}}",
				serv_info->serv_path, b_svc);

		for (l1 = serv_info->char_data; l1 != NULL; l1 = l1->next) {
			char_info = l1->data;

			b_char = g_variant_builder_new(G_VARIANT_TYPE("a{sa{sv}}"));
			b_char1 = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
			b_char11 = g_variant_builder_new(G_VARIANT_TYPE("ay"));
			b_char12 = g_variant_builder_new(G_VARIANT_TYPE("as"));
			b_char13 = g_variant_builder_new(G_VARIANT_TYPE("ao"));

			g_variant_builder_add(b_char1, "{sv}", "UUID",
					g_variant_new_string(char_info->char_uuid));
			g_variant_builder_add(b_char1, "{sv}", "Service",
					g_variant_new("o", serv_info->serv_path));

			if (char_info->char_value != NULL) {
				for (i = 0; i < char_info->value_length; i++)
					g_variant_builder_add(b_char11, "y",
							char_info->char_value[i]);

				g_variant_builder_add(b_char1, "{sv}", "Value",
						g_variant_new("ay", b_char11));
			}

			for (i = 0; i < g_slist_length(char_info->char_props); i++)
				g_variant_builder_add(b_char12, "s",
						g_slist_nth_data(char_info->char_props, i));

			g_variant_builder_add(b_char1, "{sv}", "Flags",
					g_variant_new("as", b_char12));
			g_variant_builder_add(b_char1, "{sv}", "Notifying",
					g_variant_new("b", notify));
			g_variant_builder_add(b_char1, "{sv}", "Unicast",
					g_variant_new("s", unicast));

			for (l2 = char_info->desc_data; l2 != NULL; l2 = l2->next) {
				desc_info = l2->data;
				g_variant_builder_add(b_char13, "o", desc_info->desc_path);
			}
			g_variant_builder_add(b_char1, "{sv}", "Descriptors",
					g_variant_new("ao", b_char13));

			g_variant_builder_add(b_char, "{sa{sv}}",
					DBUS_IF_GATTCHARACTERISTIC1, b_char1);
			g_variant_builder_add(b, "{oa{sa{sv}}}",
					char_info->char_path, b_char);

			for (l2 = char_info->desc_data; l2 != NULL; l2 = l2->next) {
				desc_info = l2->data;

				b_desc = g_variant_builder_new(G_VARIANT_TYPE("a{sa{sv}}"));
				b_desc1 = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
				b_desc11 = g_variant_builder_new(G_VARIANT_TYPE("ay"));
				b_desc12 = g_variant_builder_new(G_VARIANT_TYPE("as"));

				g_variant_builder_add(b_desc1, "{sv}", "UUID",
					g_variant_new_string(desc_info->desc_uuid));

				g_variant_builder_add(b_desc1, "{sv}", "Characteristic",
					g_variant_new("o", char_info->char_path));

				if (desc_info->desc_value != NULL) {
					for (i = 0; i < desc_info->value_length; i++)
						g_variant_builder_add(b_desc11, "y",
								desc_info->desc_value[i]);

					g_variant_builder_add(b_desc1, "{sv}", "Value",
							g_variant_new("ay", b_desc11));
				}

				for (i = 0; i < g_slist_length(desc_info->desc_props); i++)
					g_variant_builder_add(b_desc12, "s",
							g_slist_nth_data(desc_info->desc_props, i));

				g_variant_builder_add(b_desc1, "{sv}", "Flags",
						g_variant_new("as", b_desc12));

				g_variant_builder_add(b_desc, "{sa{sv}}",
						DBUS_IF_GATTDESCRIPTOR1, b_desc1);
				g_variant_builder_add(b, "{oa{sa{sv}}}", desc_info->desc_path,
						b_desc);

				g_variant_builder_unref(b_desc);
				g_variant_builder_unref(b_desc1);
				g_variant_builder_unref(b_desc11);
				g_variant_builder_unref(b_desc12);
			}

			g_variant_builder_unref(b_char);
			g_variant_builder_unref(b_char1);
			g_variant_builder_unref(b_char11);
			g_variant_builder_unref(b_char12);
			g_variant_builder_unref(b_char13);
		}

		g_dbus_method_invocation_return_value(invocation,
						g_variant_new("(a{oa{sa{sv}}})", b));

		g_variant_builder_unref(b);
		g_variant_builder_unref(b_svc);
		g_variant_builder_unref(b_svc1);
		g_variant_builder_unref(b_svc11);
	}
}

static gint _compare_svc_id(gconstpointer a, gconstpointer b)
{
	if (((bt_gatt_service *)a)->serv_id == GPOINTER_TO_INT(b))
		return 0;
	else
		return 1;
}

static gint _compare_chr_id(gconstpointer a, gconstpointer b)
{
	if (((bt_gatt_char *)a)->char_id == GPOINTER_TO_INT(b))
		return 0;
	else
		return 1;
}

static gint _compare_desc_id(gconstpointer a, gconstpointer b)
{
	if (((bt_gatt_desc *)a)->desc_id == GPOINTER_TO_INT(b))
		return 0;
	else
		return 1;
}

static gint _compare_char_path(gconstpointer a, gconstpointer b)
{
	if (strcmp(((bt_gatt_char *)a)->char_path, b) == 0)
		return 0;
	else
		return 1;
}

static gint _compare_desc_path(gconstpointer a, gconstpointer b)
{
	if (strcmp(((bt_gatt_desc *)a)->desc_path, b) == 0)
		return 0;
	else
		return 1;
}

static bt_gatt_service *_find_svc_list_by_id(unsigned int sid)
{
	GSList *list = NULL;

	list = g_slist_find_custom(hci.gatt_services, GINT_TO_POINTER(sid),
			_compare_svc_id);

	if (!list) {
		log_err("%s not found service id %d", __func__, sid);
		return NULL;
	}

	return list->data;
}

static bt_gatt_char *_find_chr_list_by_id(unsigned int sid, unsigned int cid)
{
	GSList *list = NULL;
	bt_gatt_service *svc;

	svc = _find_svc_list_by_id(sid);
	if (!svc)
		return NULL;

	list = g_slist_find_custom(svc->char_data, GINT_TO_POINTER(cid),
			_compare_chr_id);

	if (!list) {
		log_err("%s not found characteristic id %d", __func__, cid);
		return NULL;
	}

	return list->data;
}

static bt_gatt_desc *_find_desc_list_by_id(unsigned int sid, unsigned int cid,
		unsigned int did)
{
	GSList *list = NULL;
	bt_gatt_service *svc;
	bt_gatt_char *chr;

	svc = _find_svc_list_by_id(sid);
	if (!svc)
		return NULL;

	chr = _find_chr_list_by_id(sid, cid);
	if (!chr)
		return NULL;

	list = g_slist_find_custom(chr->desc_data, GINT_TO_POINTER(did),
			_compare_desc_id);

	if (!list) {
		log_err("%s not found descriptor id %d", __func__, did);
		return NULL;
	}

	return list->data;
}

static GSList *_find_chr_list_by_path(const gchar *path)
{
	GSList *l, *l1;
	bt_gatt_service *svc;

	for (l1 = hci.gatt_services; l1; l1 = g_slist_next(l1)) {
		svc = l1->data;
		l = g_slist_find_custom(svc->char_data, path, _compare_char_path);
		if (l)
			return l;
	}

	log_dbg("%s not found chracteristic in %s", __func__, path);

	return NULL;
}

static GSList *_find_desc_list(const gchar *path)
{
	GSList *l, *l1, *l2;
	bt_gatt_service *svc;
	bt_gatt_char *chr;

	for (l1 = hci.gatt_services; l1; l1 = g_slist_next(l1)) {
		svc = l1->data;

		for (l2 = svc->char_data; l2; l2 = g_slist_next(l2)) {
			chr = l2->data;

			l = g_slist_find_custom(chr->desc_data, path, _compare_desc_path);
			if (l)
				return l;
		}
	}

	log_dbg("%s not found descriptor in %s", __func__, path);

	return NULL;
}

static void _send_request(bt_gatt_req_handle *handle, guint len,
		const guchar *value)
{
	GVariantBuilder *b;

	b = g_variant_builder_new(G_VARIANT_TYPE("ay"));

	for (guint i = 0; i < len; i++)
		g_variant_builder_add(b, "y", value[i]);

	g_dbus_method_invocation_return_value(handle->invocation,
			g_variant_new("(ay)", b));

	g_variant_builder_unref(b);
}

static void _extract_value_parameter(GVariant *parameters,
		unsigned int *len, guchar **value)
{
	GVariant *v1 = NULL, *v2 = NULL;
	guchar *extracted_value;

	g_variant_get(parameters, "(@aya{sv})", &v1, NULL);
	*len = g_variant_n_children(v1);
	extracted_value = (guchar *)malloc(sizeof(guchar) * *len);

	for (guint i = 0; i < *len; i++) {
		v2 = g_variant_get_child_value(v1, i);
		extracted_value[i] = g_variant_get_byte(v2);
		g_variant_unref(v2);
	}

	*value = extracted_value;

	g_variant_unref(v1);
}

static void _char_method_call(GDBusConnection *connection, const gchar *sender,
		const gchar *object_path, const gchar *interface_name,
		const gchar *method_name, GVariant *parameters,
		GDBusMethodInvocation *invocation, gpointer user_data)
{
	bt_gatt_char *chr;
	GSList *l;

	log_dbg("%s", method_name);

	l = _find_chr_list_by_path(object_path);
	if (l == NULL) {
		log_dbg("there is no characteristic");
		g_dbus_method_invocation_return_value(invocation, NULL);
		return;
	}
	chr = g_slist_nth_data(l, 0);

	if (g_strcmp0(method_name, "ReadValue") == 0) {
		bt_gatt_req_handle handle;

		memset(&handle, 0, sizeof(bt_gatt_req_handle));
		handle.chr = chr;
		handle.invocation = invocation;
		handle.type = BT_GATT_REQ_TYPE_READ;

		if (chr->read_callback)
			chr->read_callback(&handle, chr->read_user_data);
		else
			_send_request(&handle, chr->value_length, chr->char_value);

	} else if (g_strcmp0(method_name, "WriteValue") == 0) {
		bt_gatt_req_handle handle;

		memset(&handle, 0, sizeof(bt_gatt_req_handle));
		handle.chr = chr;
		handle.type = BT_GATT_REQ_TYPE_WRITE;
		handle.invocation = invocation;

		_extract_value_parameter(parameters, &handle.len, &handle.value);

		if (chr->write_callback)
			chr->write_callback(&handle, handle.value,
				handle.len, chr->write_user_data);
		else
			bt_gatt_req_set_result(&handle, BT_GATT_REQ_STATE_TYPE_OK, NULL);

	} else if (g_strcmp0(method_name, "StartNotify") == 0) {
		if (chr->notify_callback) {
			chr->notify_callback(true, chr->notify_user_data);
			g_dbus_method_invocation_return_value(invocation, NULL);
		} else {
			g_dbus_method_invocation_return_dbus_error(invocation,
				"org.bluez.Error.NotPermitted", "Not Permitted");
		}

	} else if (g_strcmp0(method_name, "StopNotify") == 0) {
		if (chr->notify_callback) {
			chr->notify_callback(false, chr->notify_user_data);
			g_dbus_method_invocation_return_value(invocation, NULL);
		} else {
			g_dbus_method_invocation_return_dbus_error(invocation,
				"org.bluez.Error.NotPermitted", "Not Permitted");
		}
	} else if (g_strcmp0(method_name, "IndicateConfirm") == 0) {
		/* TODO */
	}
}

static void _desc_method_call(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path,
		const gchar *interface_name, const gchar *method_name,
		GVariant *parameters, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	bt_gatt_desc *desc;
	GSList *l;
	bt_gatt_req_handle handle;

	log_dbg("%s", method_name);

	l = _find_desc_list(object_path);
	if (l == NULL) {
		log_dbg("there is no descriptor");
		g_dbus_method_invocation_return_value(invocation, NULL);
		return;
	}
	desc = g_slist_nth_data(l, 0);

	memset(&handle, 0, sizeof(bt_gatt_req_handle));
	handle.chr = NULL;
	handle.desc = desc;
	handle.invocation = invocation;

	if (g_strcmp0(method_name, "ReadValue") == 0) {
		handle.type = BT_GATT_REQ_TYPE_READ;

		if (desc->read_callback)
			desc->read_callback(&handle, desc->read_user_data);
		else
			_send_request(&handle, desc->value_length, desc->desc_value);
	} else if (g_strcmp0(method_name, "WriteValue") == 0) {
		handle.type = BT_GATT_REQ_TYPE_WRITE;

		_extract_value_parameter(parameters, &handle.len, &handle.value);

		if (desc->write_callback)
			desc->write_callback(&handle, handle.value, handle.len,
					desc->write_user_data);
		else
			bt_gatt_req_set_result(&handle, BT_GATT_REQ_STATE_TYPE_OK, NULL);
	}
}

static void register_service_cb(GObject *object, GAsyncResult *res,
		gpointer user_data)
{
	GVariant *v;
	GError *e = NULL;

	v = g_dbus_connection_call_finish(hci.conn, res, &e);
	if (e != NULL) {
		log_dbg("%s", e->message);
		g_clear_error(&e);
	}
	log_dbg("gatt service registered");

	g_variant_unref(v);
}

static const GDBusInterfaceVTable serv_interface_vtable = {
	.method_call = _serv_method_call,
	.get_property = NULL,
	.set_property = NULL,
};

static const GDBusInterfaceVTable char_interface_vtable = {
	.method_call = _char_method_call,
	.get_property = NULL,
	.set_property = NULL,
};

static const GDBusInterfaceVTable desc_interface_vtable = {
	.method_call = _desc_method_call,
	.get_property = NULL,
	.set_property = NULL,
};

static void _set_char_properties(int properties, GSList **list)
{
	if (properties == 0x00) {
		*list = g_slist_append(*list, "read");
		return;
	}

	if (properties & BT_GATT_CHAR_PROPERTY_BROADCAST)
		*list = g_slist_append(*list, "broadcast");

	if (properties & BT_GATT_CHAR_PROPERTY_READ)
		*list = g_slist_append(*list, "read");

	if (properties & BT_GATT_CHAR_PROPERTY_WRITE_NO_RESPONSE)
		*list = g_slist_append(*list, "write-without-response");

	if (properties & BT_GATT_CHAR_PROPERTY_WRITE)
		*list = g_slist_append(*list, "write");

	if (properties & BT_GATT_CHAR_PROPERTY_NOTIFY)
		*list = g_slist_append(*list, "notify");

	if (properties & BT_GATT_CHAR_PROPERTY_INDICATE)
		*list = g_slist_append(*list, "indicate");

	if (properties & BT_GATT_CHAR_PROPERTY_SIGNED_WRITE)
		*list = g_slist_append(*list, "authenticated-signed-writes");
}

static void _set_desc_properties(int properties, GSList **list)
{
	if (properties == 0x00) {
		*list = g_slist_append(*list, "read");
		return;
	}

	if (properties & BT_GATT_DESC_PROPERTY_READ)
		*list = g_slist_append(*list, "read");

	if (properties & BT_GATT_DESC_PROPERTY_WRITE)
		*list = g_slist_append(*list, "write");

	if (properties & BT_GATT_DESC_PROPERTY_ENC_READ)
		*list = g_slist_append(*list, "encrypt-read");

	if (properties & BT_GATT_DESC_PROPERTY_ENC_WRITE)
		*list = g_slist_append(*list, "encrypt-write");

	if (properties & BT_GATT_DESC_PROPERTY_ENC_AUTH_READ)
		*list = g_slist_append(*list, "encrypt-authenticated-read");

	if (properties & BT_GATT_DESC_PROPERTY_ENC_AUTH_WRITE)
		*list = g_slist_append(*list, "encrypt-authenticated-write");

	if (properties & BT_GATT_DESC_PROPERTY_SEC_READ)
		*list = g_slist_append(*list, "secure-read");

	if (properties & BT_GATT_DESC_PROPERTY_SEC_WRITE)
		*list = g_slist_append(*list, "secure-write");
}

artik_error bt_gatt_add_service(artik_bt_gatt_service svc, int *id)
{
	guint num;
	gchar *path = NULL;
	bt_gatt_service *serv_info = NULL;

	log_dbg("%s", __func__);

	num = g_slist_length(hci.gatt_services);
	path = g_strdup_printf("%s%d", GATT_SERVICE_PREFIX, num);

	serv_info = g_new0(bt_gatt_service, 1);
	serv_info->serv_path = g_strdup(path);
	serv_info->serv_id = num;
	serv_info->service_uuid = g_strdup(svc.uuid);
	serv_info->is_svc_registered = FALSE;
	serv_info->is_svc_primary = svc.primary;

	hci.gatt_services = g_slist_append(hci.gatt_services, serv_info);

	*id = num;

	g_free(path);

	return S_OK;
}

artik_error bt_gatt_add_characteristic(int svc_id, artik_bt_gatt_chr chr,
		int *id)
{
	GError *error = NULL;
	GSList *prop_list = NULL;
	gchar *path = NULL;
	guint object_id, num;
	bt_gatt_service *service = NULL;
	bt_gatt_char *characteristic = NULL;
	artik_error ret = S_OK;

	log_dbg("%s sid: %d", __func__, svc_id);

	if (chr.uuid == NULL)
		return E_BT_ERROR;

	service = _find_svc_list_by_id(svc_id);
	if (!service)
		return E_BT_ERROR;

	num = g_slist_length(service->char_data);

	path = g_strdup_printf("%s%d%s%d", GATT_SERVICE_PREFIX, svc_id,
			GATT_CHARACTERISTIC_PREFIX, num);

	if (!characteristic_node_info)
		characteristic_node_info = g_dbus_node_info_new_for_xml(
			char_introspection_xml, &error);

	ret = bt_check_error(error);
	if (ret != S_OK)
		goto exit;

	object_id = g_dbus_connection_register_object(
			hci.conn,
			path,
			characteristic_node_info->interfaces[0],
			&char_interface_vtable,
			NULL, NULL, &error);

	ret = bt_check_error(error);
	if (ret != S_OK)
		goto exit;

	log_dbg("%s %s added", __func__, path);

	_set_char_properties(chr.property, &prop_list);

	characteristic = g_new0(bt_gatt_char, 1);

	characteristic->char_path = g_strdup(path);
	characteristic->char_id = num;
	characteristic->char_uuid = g_strdup(chr.uuid);
	characteristic->char_props = prop_list;
	characteristic->service = service;
	if (chr.length > 0) {
		characteristic->char_value = (guchar *)malloc(sizeof(guchar)
				* chr.length);
		memcpy(characteristic->char_value, chr.value, chr.length);
		characteristic->value_length = chr.length;
	} else {
		characteristic->value_length = 0;
	}
	characteristic->reg_id = object_id;

	service->char_data = g_slist_append(service->char_data, characteristic);

	ret = bt_check_error(error);
	if (ret != S_OK)
		goto exit;

	*id = num;

exit:
	g_free(path);

	return ret;
}

artik_error bt_gatt_add_descriptor(int service_id, int char_id,
		artik_bt_gatt_desc desc, int *id)
{
	GError *error = NULL;

	GSList *prop_list = NULL;
	gchar *path = NULL;
	guint object_id, num;
	bt_gatt_service *service = NULL;
	bt_gatt_char *characteristic = NULL;
	bt_gatt_desc *descriptor = NULL;
	artik_error ret = S_OK;

	log_dbg("%s sid: %d, cid: %d", __func__, service_id, char_id);

	service = _find_svc_list_by_id(service_id);
	if (!service)
		return E_BT_ERROR;

	characteristic = _find_chr_list_by_id(service_id, char_id);
	if (!characteristic)
		return E_BT_ERROR;

	num = g_slist_length(characteristic->desc_data);

	path = g_strdup_printf("%s%d%s%d%s%d",
			GATT_SERVICE_PREFIX, service_id,
			GATT_CHARACTERISTIC_PREFIX, char_id,
			GATT_DESCRIPTOR_PREFIX, num);

	if (!descriptor_node_info)
		descriptor_node_info = g_dbus_node_info_new_for_xml(
			descriptor_introspection_xml, &error);

	ret = bt_check_error(error);
	if (ret != S_OK)
		goto exit;

	object_id = g_dbus_connection_register_object(
			hci.conn,
			path,
			descriptor_node_info->interfaces[0],
			&desc_interface_vtable,
			NULL, NULL, &error);

	ret = bt_check_error(error);
	if (ret != S_OK)
		goto exit;

	_set_desc_properties(desc.property, &prop_list);

	descriptor = g_new0(bt_gatt_desc, 1);

	if (desc.length > 0) {
		descriptor->desc_value = (guchar *)malloc(sizeof(guchar) * desc.length);
		if (!descriptor->desc_value) {
			g_free(descriptor);
			g_free(path);
			return E_BT_ERROR;
		}

		memcpy(descriptor->desc_value, desc.value, desc.length);
		descriptor->value_length = desc.length;
	} else {
		descriptor->value_length = 0;
	}
	descriptor->desc_path = g_strdup(path);
	descriptor->desc_id = num;
	descriptor->desc_uuid = g_strdup(desc.uuid);
	descriptor->desc_props = prop_list;
	descriptor->chr = characteristic;
	descriptor->reg_id = object_id;

	characteristic->desc_data = g_slist_append(characteristic->desc_data,
			descriptor);

	*id = num;

exit:
	g_free(path);

	return ret;
}

artik_error bt_gatt_remove_service(int sid)
{
	bt_gatt_service *svc = NULL;

	log_dbg("%s sid: %d", __func__, sid);

	svc = _find_svc_list_by_id(sid);
	if (!svc)
		return E_BT_ERROR;

	hci.gatt_services = g_slist_remove(hci.gatt_services, svc);
	g_dbus_connection_unregister_object(hci.conn, svc->reg_id);

	g_free(svc->serv_path);
	g_free(svc->service_uuid);
	g_free(svc);

	if (g_slist_length(hci.gatt_services) == 0)
		g_dbus_node_info_unref(service_node_info);

	return S_OK;
}

artik_error bt_gatt_remove_characteristic(int sid, int cid)
{
	bt_gatt_service *svc = NULL;
	bt_gatt_char *chr = NULL;

	log_dbg("%s sid: %d, cid: %d", __func__, sid, cid);

	svc = _find_svc_list_by_id(sid);
	if (!svc)
		return E_BT_ERROR;

	chr = _find_chr_list_by_id(sid, cid);
	if (!chr)
		return E_BT_ERROR;

	g_dbus_connection_unregister_object(hci.conn, chr->reg_id);
	g_slist_free(chr->char_props);
	svc->char_data = g_slist_remove(svc->char_data, chr);

	g_free(chr->char_path);
	g_free(chr->char_uuid);
	g_free(chr->char_value);
	g_free(chr);

	if (g_slist_length(svc->char_data) == 0)
		g_dbus_node_info_unref(characteristic_node_info);

	return S_OK;
}

artik_error bt_gatt_remove_descriptor(int sid, int cid, int did)
{
	bt_gatt_service *svc = NULL;
	bt_gatt_char *chr = NULL;
	bt_gatt_desc *desc = NULL;

	log_dbg("%s sid: %d, cid: %d, did: %d", __func__, sid, cid, did);

	svc = _find_svc_list_by_id(sid);
	if (!svc)
		return E_BT_ERROR;

	chr = _find_chr_list_by_id(sid, cid);
	if (!chr)
		return E_BT_ERROR;

	desc = _find_desc_list_by_id(sid, cid, did);
	if (!desc)
		return E_BT_ERROR;

	g_dbus_connection_unregister_object(hci.conn, desc->reg_id);
	chr->desc_data = g_slist_remove(chr->desc_data, desc);

	g_slist_free(desc->desc_props);
	g_free(desc->desc_path);
	g_free(desc->desc_uuid);
	g_free(desc->desc_value);
	g_free(desc);

	if (g_slist_length(chr->desc_data) == 0)
		g_dbus_node_info_unref(descriptor_node_info);

	return S_OK;
}

artik_error bt_gatt_set_char_on_read_request(int svc_id, int char_id,
		artik_bt_gatt_req_read callback, void *user_data)
{
	bt_gatt_char *chr = _find_chr_list_by_id(svc_id, char_id);

	if (!chr)
		return E_BAD_ARGS;

	chr->read_callback = callback;
	chr->read_user_data = user_data;

	return S_OK;
}

artik_error bt_gatt_set_char_on_write_request(int svc_id, int char_id,
		artik_bt_gatt_req_write callback, void *user_data)
{
	bt_gatt_char *chr = _find_chr_list_by_id(svc_id, char_id);

	if (!chr)
		return E_BAD_ARGS;

	chr->write_callback = callback;
	chr->write_user_data = user_data;

	return S_OK;
}

artik_error bt_gatt_set_char_on_notify_request(int svc_id, int char_id,
		artik_bt_gatt_req_notify callback, void *user_data)
{
	bt_gatt_char *chr = _find_chr_list_by_id(svc_id, char_id);

	if (!chr)
		return E_BAD_ARGS;

	chr->notify_callback = callback;
	chr->notify_user_data = user_data;

	return S_OK;
}

artik_error bt_gatt_set_desc_on_read_request(int svc_id, int char_id,
		int desc_id, artik_bt_gatt_req_read callback, void *user_data)
{
	bt_gatt_desc *desc = _find_desc_list_by_id(svc_id, char_id, desc_id);

	if (!desc)
		return E_BAD_ARGS;

	desc->read_callback = callback;
	desc->read_user_data = user_data;

	return S_OK;
}

artik_error bt_gatt_set_desc_on_write_request(int svc_id, int char_id,
		int desc_id, artik_bt_gatt_req_write callback, void *user_data)
{
	bt_gatt_desc *desc = _find_desc_list_by_id(svc_id, char_id, desc_id);

	if (!desc)
		return E_BAD_ARGS;

	desc->write_callback = callback;
	desc->write_user_data = user_data;

	return S_OK;
}

int bt_gatt_register_service(int sid)
{
	GError *e = NULL;
	bt_gatt_service *svc = NULL;
	guint id;

	svc = _find_svc_list_by_id(sid);
	if (!svc)
		return E_BT_ERROR;

	log_dbg("%s sid: %d, path: %s", __func__, sid, svc->serv_path);

	if (!service_node_info)
		service_node_info = g_dbus_node_info_new_for_xml(
			service_introspection_xml, &e);
	if (e) {
		log_err(e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	id = g_dbus_connection_register_object(hci.conn, svc->serv_path,
			service_node_info->interfaces[0], &serv_interface_vtable,
			svc, NULL, &e);
	if (e) {
		log_err(e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}
	svc->reg_id = id;

	g_dbus_connection_call(
		hci.conn,
		DBUS_BLUEZ_BUS,
		DBUS_BLUEZ_OBJECT_PATH_HCI0,
		DBUS_IF_GATTMANAGER1,
		"RegisterApplication",
		g_variant_new("(oa{sv})", svc->serv_path, NULL),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL,
		(GAsyncReadyCallback)register_service_cb, NULL);

	return S_OK;
}

artik_error bt_gatt_req_set_value(artik_bt_gatt_req request, int len,
		const unsigned char *value)
{
	bt_gatt_req_handle *handle = request;
	bt_gatt_char *chr = handle->chr;
	bt_gatt_desc *desc = handle->desc;
	unsigned char **val = NULL;
	unsigned int *ptr_len = NULL;

	if (handle->type != BT_GATT_REQ_TYPE_READ)
		return E_BAD_ARGS;

	if (chr) {
		val = &chr->char_value;
		ptr_len = &chr->value_length;
	} else if (desc) {
		val = &desc->desc_value;
		ptr_len = &desc->value_length;
	}

	if (!val)
		return E_BAD_ARGS;

	if (*val)
		free(*val);

	*val = malloc(sizeof(unsigned char)*len);
	*ptr_len = len;
	memcpy(*val, value, len);

	_send_request(handle, len, value);

	return S_OK;
}

static artik_error _return_dbus_state(
	bt_gatt_req_handle *handle,
	artik_bt_gatt_req_state_type state, const char *err_msg)
{
	const char *error_type = NULL;

	switch (state) {
	case BT_GATT_REQ_STATE_TYPE_OK:
		if (handle->type != BT_GATT_REQ_TYPE_WRITE)
			return E_BAD_ARGS;

		g_dbus_method_invocation_return_value(handle->invocation, NULL);
		return S_OK;
	case BT_GATT_REQ_STATE_TYPE_FAILED:
		error_type = "org.bluez.Error.Failed";
		break;
	case BT_GATT_REQ_STATE_TYPE_IN_PROGRESS:
		error_type = "org.bluez.Error.InProgress";
		break;
	case BT_GATT_REQ_STATE_TYPE_NOT_PERMITTED:
		if (handle->type == BT_GATT_REQ_TYPE_NOTIFY)
			return E_BAD_ARGS;
		error_type = "org.bluez.Error.NotPermitted";
		break;
	case BT_GATT_REQ_STATE_TYPE_INVALID_VALUE_LENGTH:
		if (handle->type != BT_GATT_REQ_TYPE_WRITE)
			return E_BAD_ARGS;

		error_type = "org.bluez.Error.InvalidValueLength";
		break;
	case BT_GATT_REQ_STATE_TYPE_NOT_AUTHORIZED:
		if (handle->type == BT_GATT_REQ_TYPE_NOTIFY)
			return E_BAD_ARGS;
		error_type = "org.bluez.Error.NotAuthorized";
		break;
	case BT_GATT_REQ_STATE_TYPE_NOT_SUPPORTED:
		error_type = "org.bluez.Error.NotSupported";
		break;
	}

	g_dbus_method_invocation_return_dbus_error(handle->invocation, error_type,
			err_msg);
	return S_OK;
}

artik_error bt_gatt_req_set_result(artik_bt_gatt_req request,
		artik_bt_gatt_req_state_type state, const char *err_msg)
{
	bt_gatt_req_handle *handle = request;

	if (handle->type == BT_GATT_REQ_TYPE_WRITE
			&& state == BT_GATT_REQ_STATE_TYPE_OK) {
		if (handle->chr) {
			g_free(handle->chr->char_value);
			handle->chr->value_length = handle->len;
			handle->chr->char_value = handle->value;
		} else if (handle->desc) {
			g_free(handle->desc->desc_value);
			handle->desc->value_length = handle->len;
			handle->desc->desc_value = handle->value;
		}
	}

	artik_error err = _return_dbus_state(handle, state, err_msg);

	if (err != S_OK)
		return err;

	if (state != BT_GATT_REQ_STATE_TYPE_OK && handle->value)
		free(handle->value);

	return S_OK;
}

int bt_gatt_unregister_service(int id)
{
	bt_gatt_service *svc = NULL;

	svc = _find_svc_list_by_id(id);
	if (!svc)
		return E_BT_ERROR;

	log_dbg("%s sid:%d, path: %s", __func__, id, svc->serv_path);

	g_dbus_connection_call(
		hci.conn,
		DBUS_BLUEZ_BUS,
		DBUS_BLUEZ_OBJECT_PATH_HCI0,
		DBUS_IF_GATTMANAGER1,
		"UnregisterApplication",
		g_variant_new("(o)", svc->serv_path, NULL),
		NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, NULL, NULL);

	return S_OK;
}

int bt_gatt_notify(int service_id, int char_id, unsigned char *byte, int len)
{
	GVariantBuilder *b1, *b11;
	int i = 0;

	if (len <= 0)
		return E_BT_ERROR;

	bt_gatt_char *chr = _find_chr_list_by_id(service_id, char_id);

	if (!chr)
		return E_BT_ERROR;

	b1 = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	b11 = g_variant_builder_new(G_VARIANT_TYPE("ay"));

	for (i = 0; i < len; i++)
		g_variant_builder_add(b11, "y", byte[i]);

	g_variant_builder_add(b1, "{sv}", "Value", g_variant_new("ay", b11));

	if (chr->char_value)
		free(chr->char_value);

	chr->value_length = len;
	chr->char_value = malloc(sizeof(unsigned char)*len);
	memcpy(chr->char_value, byte, len);
	g_dbus_connection_emit_signal(hci.conn, DBUS_BLUEZ_BUS, chr->char_path,
			DBUS_IF_PROPERTIES, "PropertiesChanged", g_variant_new("(sa{sv}as)",
			DBUS_IF_GATTCHARACTERISTIC1, b1, NULL), NULL);

	g_variant_builder_unref(b1);
	g_variant_builder_unref(b11);

	return S_OK;
}
