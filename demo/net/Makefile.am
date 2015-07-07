demodir = @XENO_DEMO_DIR@

CCLD = $(top_srcdir)/scripts/wrap-link.sh $(CC)

demo_PROGRAMS = 	\
	mcast-receiver	\
	mcast-sender	\
	raw-ethernet	\
	rttcp-client	\
	rttcp-server	\
	rtt-mcast-measure	\
	rtt-mcast-responder	\
	rtt-responder	\
	rtt-sender	\
	udp-send

cppflags = 			\
	$(XENO_USER_CFLAGS)	\
	-I$(top_srcdir)/include

ldflags = @XENO_AUTOINIT_LDFLAGS@ $(XENO_POSIX_WRAPPERS)

ldadd = 					\
	 @XENO_CORE_LDADD@			\
	 @XENO_USER_LDADD@			\
	-lpthread -lrt

mcast_receiver_SOURCES = mcast-receiver.c
mcast_receiver_CPPFLAGS = $(cppflags)
mcast_receiver_LDFLAGS = $(ldflags)
mcast_receiver_LDADD = $(ldadd)

mcast_sender_SOURCES = mcast-sender.c
mcast_sender_CPPFLAGS = $(cppflags)
mcast_sender_LDFLAGS = $(ldflags)
mcast_sender_LDADD = $(ldadd)

raw_ethernet_SOURCES = raw-ethernet.c
raw_ethernet_CPPFLAGS = $(cppflags)
raw_ethernet_LDFLAGS = $(ldflags)
raw_ethernet_LDADD = $(ldadd)

rttcp_client_SOURCES = rttcp-client.c
rttcp_client_CPPFLAGS = $(cppflags)
rttcp_client_LDFLAGS = $(ldflags)
rttcp_client_LDADD = $(ldadd)

rttcp_server_SOURCES = rttcp-server.c
rttcp_server_CPPFLAGS = $(cppflags)
rttcp_server_LDFLAGS = $(ldflags)
rttcp_server_LDADD = $(ldadd)

rtt_mcast_measure_SOURCES = rtt-mcast-measure.c
rtt_mcast_measure_CPPFLAGS = $(cppflags)
rtt_mcast_measure_LDFLAGS = $(ldflags)
rtt_mcast_measure_LDADD = ../../lib/alchemy/libalchemy.la 	\
		../../lib/copperplate/libcopperplate.la		\
		$(ldadd)

rtt_mcast_responder_SOURCES = rtt-mcast-responder.c
rtt_mcast_responder_CPPFLAGS = $(cppflags)
rtt_mcast_responder_LDFLAGS = $(ldflags)
rtt_mcast_responder_LDADD = $(ldadd)

rtt_responder_SOURCES = rtt-responder.c
rtt_responder_CPPFLAGS = $(cppflags)
rtt_responder_LDFLAGS = $(ldflags)
rtt_responder_LDADD = $(ldadd)

rtt_sender_SOURCES = rtt-sender.c
rtt_sender_CPPFLAGS = $(cppflags)
rtt_sender_LDFLAGS = $(ldflags)
rtt_sender_LDADD = $(ldadd)

udp_send_SOURCES = udp-send.c
udp_send_CPPFLAGS = $(cppflags)
udp_send_LDFLAGS = $(ldflags)
udp_send_LDADD = $(ldadd)
