// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package ofp14

const (
	// Immutable messages (symmetric)

	OFPT_HELLO        = 0
	OFPT_ERROR        = 1
	OFPT_ECHO_REQUEST = 2
	OFPT_ECHO_REPLY   = 3
	OFPT_EXPERIMENTER = 4

	// Switch configuration messages

	OFPT_FEATURES_REQUEST   = 5
	OFPT_FEATURES_REPLY     = 6
	OFPT_GET_CONFIG_REQUEST = 7
	OFPT_GET_CONFIG_REPLY   = 8
	OFPT_SET_CONFIG         = 9

	// Asynchronous messages

	OFPT_PACKET_IN    = 10
	OFPT_FLOW_REMOVED = 11
	OFPT_PORT_STATUS  = 12

	// Controller command messages

	OFPT_PACKET_OUT = 13
	OFPT_FLOW_MOD   = 14
	OFPT_GROUP_MOD  = 15
	OFPT_PORT_MOD   = 16
	OFPT_TABLE_MOD  = 17

	// Multipart messages

	OFPT_MULTIPART_REQUEST = 18
	OFPT_MULTIPART_REPLY   = 19

	// Barrier messages

	OFPT_BARRIER_REQUEST = 20
	OFPT_BARRIER_REPLY   = 21

	// Queue Configuration messages

	OFPT_QUEUE_GET_CONFIG_REQUEST = 22
	OFPT_QUEUE_GET_CONFIG_REPLY   = 23

	// Controller role change request messages

	OFPT_ROLE_REQUEST = 24
	OFPT_ROLE_REPLY   = 25

	// Asynchronous message configuration

	OFPT_GET_ASYNC_REQUEST = 26
	OFPT_GET_ASYNC_REPLY   = 27
	OFPT_SET_ASYNC         = 28

	// Meters and rate limiters configuration messages

	OFPT_METER_MOD = 29
	OFPT_MAX_TYPE  = 29

	/*
		Header OF 1.3.0:
		0		1		2		3
		+---------------------------------------------------------------+
		|version       	|type	       	|length				|
		+---------------------------------------------------------------+
		|xid								|
		+---------------------------------------------------------------+


		PacketIn OF 1.3.0:
		+---------------------------------------------------------------+
		|version        |type	        |length				|
		+---------------------------------------------------------------+
		|xid								|
		+---------------------------------------------------------------+
		|buffer_id							|
		+---------------------------------------------------------------+
		|total_len	                |reason	        |tbl_id		|
		+---------------------------------------------------------------+
		|cookie								|
		|>> 								|
		+---------------------------------------------------------------+
		|ofp_match (multiple of 8)					|
		...								|
		+---------------------------------------------------------------+
		|pad			        | data        			|
		+---------------------------------------------------------------+
		... (length inferred from header.length) 			|
		+---------------------------------------------------------------+


		ofp_match:
		+---------------------------------------------------------------+
		|type				|length				|
		+---------------------------------------------------------------+
		...
		+---------------------------------------------------------------+

		The first 2 fields are followed by:
		- exactly length-4 (possibly 0) bytes containing OXM TLVs, then
		- exactly ((length+7)/8*8 - length) (between 0 and 7) bytes of
		  all-zero bytes

		OXM TLVs:
		+---------------------------------------------------------------+
		|oxm_class	 		|oxm_field	|oxm_length	|
		+---------------------------------------------------------------+
		| <oxm_length> bytes						|
		|                       +---------------------------------------+
		...			|
		+-----------------------+

		In summary, 'Match' is padded as needed, to make its
		overall size a multiple of 8, to preserve alignment in
		structures using it.


		FlowMod OF 1.3.0:
		+---------------------------------------------------------------+
		|version        |type	        |length				|
		+---------------------------------------------------------------+
		|xid								|
		+---------------------------------------------------------------+
		|cookie								|
		|>>								|
		+---------------------------------------------------------------+
		|cookie mask							|
		|>>								|
		+---------------------------------------------------------------+
		|table_id       |cmd	        |idle timeout			|
		+---------------------------------------------------------------+
		|hard_timeout		        |priority			|
		+---------------------------------------------------------------+
		|buffer_id							|
		+---------------------------------------------------------------+
		|out_port							|
		+---------------------------------------------------------------+
		|out_group							|
		+---------------------------------------------------------------+
		|flags			        |pad				|
		+---------------------------------------------------------------+
		|ofp_match (multiple of 8)					|
		...								|
		+---------------------------------------------------------------+
		|instruction							|
		...								|
		+---------------------------------------------------------------+



	*/

	PKTIN_OFPMATCH_OFFSET = 24 // offset of 'ofp_match' field within a PKTIN
	PKTIN_PAD_BYTES       = 2

	OFPMATCH_TYPE_OFFSET   = 0 // offset of 'ofp_match.type' field from ofp_match
	OFPMATCH_LENGTH_OFFSET = 2 // offset of 'ofp_match.length' field from ofp_match
	OFPMATCH_LENGTH_BYTES  = 2 // offset of 'ofp_match.length' field from ofp_match
	OFPMATCH_OXM0_OFFSET   = 4 // offset of first OXM field from ofp_match

	OXM_CLASS_OFFSET  = 0
	OXM_FIELD_OFFSET  = 2
	OXM_LENGTH_OFFSET = 3
	OXM_VALUE_OFFSET  = 4

	FLOWMOD_MATCH_OFFSET = 48 // offset of 'match' field within a FLOWMOD

	// OXM0: the first OXM TLV

	FLOWMOD_MATCH_OXM0_OFFSET = 52

	OFPXMC_OPENFLOW_BASIC = 0x8000
	OFPXMT_OFB_ETH_DST    = 0x06
	OFPXMT_OFB_ETH_SRC    = 0x08

	ETHER_DSTMAC_OFFSET    = 0
	ETHER_SRCMAC_OFFSET    = 6
	ETHER_ETHERTYPE_OFFSET = 12
	ETHER_DATA_OFFSET      = 14
)
