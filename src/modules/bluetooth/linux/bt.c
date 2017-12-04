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

#include <artik_bluetooth.h>

#include "core.h"

artik_error bt_init(void)
{
	GError *e = NULL;
	guint subscribe_id;

	log_dbg("%s", __func__);

	if (hci.refcnt++)
		return S_OK;

	hci.conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &e);
	if (e != NULL) {
		log_err("%s", e->message);
		hci.refcnt = 0;
		g_error_free(e);
		return E_BT_ERROR;
	}

	if (hci.subscribe_ids == NULL)
		hci.subscribe_ids = g_hash_table_new(g_str_hash, g_str_equal);

	subscribe_id = g_dbus_connection_signal_subscribe(hci.conn,
			NULL, DBUS_IF_OBJECT_MANAGER, "InterfacesAdded",
			NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE, _dbus_signal_callback,
			NULL, NULL);

	g_hash_table_insert(hci.subscribe_ids,
			"InterfacesAdded", GUINT_TO_POINTER(subscribe_id));

	subscribe_id = g_dbus_connection_signal_subscribe(hci.conn,
			NULL, DBUS_IF_OBJECT_MANAGER, "InterfacesRemoved",
			NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE, _dbus_signal_callback,
			NULL, NULL);

	g_hash_table_insert(hci.subscribe_ids,
			"InterfacesRemoved", GUINT_TO_POINTER(subscribe_id));

	subscribe_id = g_dbus_connection_signal_subscribe(hci.conn,
			NULL, DBUS_IF_PROPERTIES, "PropertiesChanged",
			NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE, _dbus_signal_callback,
			NULL, NULL);

	g_hash_table_insert(hci.subscribe_ids,
		"PropertiesChanged", GUINT_TO_POINTER(subscribe_id));

	return S_OK;
}

artik_error bt_deinit(void)
{
	GError *e = NULL;

	log_dbg("%s", __func__);

	if (!hci.refcnt || --hci.refcnt)
		return S_OK;

	g_dbus_connection_signal_unsubscribe(hci.conn,
		GPOINTER_TO_INT(g_hash_table_lookup(hci.subscribe_ids,
			"InterfacesAdded")));

	g_dbus_connection_signal_unsubscribe(hci.conn,
		GPOINTER_TO_INT(g_hash_table_lookup(hci.subscribe_ids,
			"InterfacesRemoved")));

	g_dbus_connection_signal_unsubscribe(hci.conn,
		GPOINTER_TO_INT(g_hash_table_lookup(hci.subscribe_ids,
			"PropertiesChanged")));

	if (hci.subscribe_ids)
		g_hash_table_destroy(hci.subscribe_ids);

	g_slist_free(hci.advertisements);
	g_slist_free(hci.gatt_services);
	g_slist_free(hci.gatt_clients);

	g_dbus_connection_close_sync(hci.conn, NULL, &e);
	if (e != NULL) {
		log_err("%s", e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	return S_OK;
}

artik_error _bt_init_session(void)
{
	GError *e = NULL;
	guint ses_subscribe_id;

	log_dbg("%s", __func__);

	hci.session_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &e);
	if (e != NULL) {
		log_err("%s", e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	if (hci.ses_subscribe_ids == NULL)
		hci.ses_subscribe_ids = g_hash_table_new(g_str_hash, g_str_equal);

	ses_subscribe_id = g_dbus_connection_signal_subscribe(hci.session_conn,
				NULL, DBUS_IF_OBJECT_MANAGER, "InterfacesAdded",
				NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE, _dbus_signal_callback,
				NULL, NULL);

	g_hash_table_insert(hci.ses_subscribe_ids,
			"InterfacesAdded", GUINT_TO_POINTER(ses_subscribe_id));

	ses_subscribe_id = g_dbus_connection_signal_subscribe(hci.session_conn,
				NULL, DBUS_IF_OBJECT_MANAGER, "InterfacesRemoved",
				NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE, _dbus_signal_callback,
				NULL, NULL);

	g_hash_table_insert(hci.ses_subscribe_ids,
				"InterfacesRemoved", GUINT_TO_POINTER(ses_subscribe_id));

	ses_subscribe_id = g_dbus_connection_signal_subscribe(hci.session_conn,
				NULL, DBUS_IF_PROPERTIES, "PropertiesChanged",
				NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE, _dbus_signal_callback,
				NULL, NULL);

	g_hash_table_insert(hci.ses_subscribe_ids,
			"PropertiesChanged", GUINT_TO_POINTER(ses_subscribe_id));

	return S_OK;
}

artik_error _bt_deinit_session(void)
{
	GError *e = NULL;

	log_dbg("%s", __func__);

	g_dbus_connection_signal_unsubscribe(hci.session_conn,
		GPOINTER_TO_INT(g_hash_table_lookup(hci.ses_subscribe_ids,
			"InterfacesAdded")));

	g_dbus_connection_signal_unsubscribe(hci.session_conn,
		GPOINTER_TO_INT(g_hash_table_lookup(hci.ses_subscribe_ids,
			"InterfacesRemoved")));

	g_dbus_connection_signal_unsubscribe(hci.session_conn,
		GPOINTER_TO_INT(g_hash_table_lookup(hci.ses_subscribe_ids,
			"PropertiesChanged")));

	if (hci.ses_subscribe_ids)
		g_hash_table_destroy(hci.ses_subscribe_ids);

	g_dbus_connection_close_sync(hci.session_conn, NULL, &e);
	if (e != NULL) {
		log_err("%s", e->message);
		g_error_free(e);
		return E_BT_ERROR;
	}

	return S_OK;
}

artik_error bt_set_callback(artik_bt_event event,
		artik_bt_callback user_callback, void *user_data)
{
	if (event >= BT_EVENT_END)
		return E_BAD_ARGS;
	hci.callback[event].fn = user_callback;
	hci.callback[event].user_data = user_data;

	return S_OK;
}

artik_error bt_set_callbacks(artik_bt_callback_property *user_callbacks,
	unsigned int size)
{
	artik_bt_event bt_event;
	unsigned int callback_num;

	if ((!user_callbacks) || (size <= 0))
		return E_BAD_ARGS;

	for (callback_num = 0; callback_num < size;
		user_callbacks++, callback_num++) {
		bt_event = user_callbacks->event;

		if ((bt_event < 0) || (bt_event >= BT_EVENT_END))
			continue;

		hci.callback[bt_event].fn = user_callbacks->fn;
		hci.callback[bt_event].user_data = user_callbacks->user_data;
	}
	return S_OK;
}

artik_error bt_unset_callback(artik_bt_event event)
{
	if (event >= BT_EVENT_END)
		return E_BAD_ARGS;

	hci.callback[event].fn = NULL;
	hci.callback[event].user_data = NULL;

	return S_OK;
}
