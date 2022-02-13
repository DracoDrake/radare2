/* radare - LGPL - Copyright 2022 - pancake */

#include <r_util.h>
#include <r_list.h>

R_API RThreadChannel *r_th_channel_new(void) {
	R_LOG_DEBUG ("r_th_channel_new");
	RThreadChannel *tc = R_NEW0 (RThreadChannel);
	if (tc) {
		tc->sem = r_th_sem_new (1);
		r_th_sem_wait (tc->sem); // busy because stack is empty
		tc->lock = r_th_lock_new (true);
		tc->stack = r_list_newf ((RListFree)r_th_channel_message_free);
	}
	return tc;
}

R_API void r_th_channel_free(RThreadChannel *tc) {
	R_LOG_DEBUG ("r_th_channel_free");
	if (tc) {
		r_list_free (tc->stack);
		r_th_lock_free (tc->lock);
		free (tc);
	}
}

R_API RThreadChannelMessage *r_th_channel_message_new(const ut8 *msg, int len) {
	R_LOG_DEBUG ("r_th_channel_message_new");
	RThreadChannelMessage *cm = R_NEW (RThreadChannelMessage);
	if (cm) {
		cm->msg = r_mem_dup (msg, len);
		cm->len = len;
		cm->sem = r_th_sem_new (1);
		// r_th_sem_wait (cm->sem); // busy because stack is empty
		cm->lock = r_th_lock_new (false); // locked here
	}
	return cm;
}

R_API RThreadChannelMessage *r_th_channel_message_read(RThreadChannel *tc, RThreadChannelMessage *cm) {
	R_LOG_DEBUG ("r_th_channel_message_read");
	if (cm) {
		eprintf ("wait\n");
		r_th_sem_wait (cm->sem);
		eprintf ("waited\n");
	} else {
		eprintf ("not waited\n");
		// r_ref (cm);
	}
	return cm;
}

R_API RThreadChannelMessage *r_th_channel_write(RThreadChannel *tc, RThreadChannelMessage *cm) {
	R_LOG_DEBUG ("r_th_channel_write");
	r_return_val_if_fail (tc && cm, NULL);
	r_th_lock_enter (cm->lock);
r_sys_backtrace ();
	RThreadChannelMessage *m = r_th_channel_message_new (cm->msg, cm->len);
	if (m) {
eprintf ("PUSHING MSG prelock\n");
		r_th_lock_enter (tc->lock);
eprintf ("PUSHING MSG postlock\n");
		r_list_push (tc->stack, m);
		r_th_lock_leave (tc->lock);
	//	r_th_lock_leave (cm->lock);
eprintf ("jejej(a)%c", 10);
	}
	r_th_lock_leave (cm->lock);
	r_th_sem_post (tc->sem);
	return m;
}

R_API void r_th_channel_message_free(RThreadChannelMessage *cm) {
	R_LOG_DEBUG ("r_th_channel_message_free");
	if (cm) {
		r_th_sem_post (cm->sem);
		r_th_sem_free (cm->sem);
		free (cm->msg);
		//r_th_lock_leave (cm->lock);
		r_th_lock_free (cm->lock);
		free (cm);
	}
}

R_API RThreadChannelMessage *r_th_channel_read(RThreadChannel *tc) {
	R_LOG_DEBUG ("r_th_channel_read");
	r_th_lock_enter (tc->lock);
	RThreadChannelMessage *msg = r_list_pop_head (tc->stack);
	if (!msg) {
eprintf ("indeed no msg\n");
		return NULL;
	}
	r_th_lock_enter (msg->lock);
	//r_th_sem_wait (msg->sem);
	//r_th_sem_post (tc->sem);
	r_th_lock_leave (tc->lock);
eprintf ("..... returning msg\n");
	return msg;
}
