// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#pragma once

#include <boost/container/flat_map.hpp>
#include "rgw_common.h"
#include "common/OutputDataSocket.h"
#include "common/versioned_variant.h"
#include <vector>
#include <fstream>
#include "rgw_sal_fwd.h"

class RGWOp;

struct delete_multi_obj_entry {
  std::string key;
  std::string version_id;
  std::string error_message;
  std::string marker_version_id;
  uint32_t http_status = 0;
  bool error = false;
  bool delete_marker = false;

  void encode(bufferlist &bl) const {
    ENCODE_START(1, 1, bl);
    encode(key, bl);
    encode(version_id, bl);
    encode(error_message, bl);
    encode(marker_version_id, bl);
    encode(http_status, bl);
    encode(error, bl);
    encode(delete_marker, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::const_iterator &p) {
    DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, p);
    decode(key, p);
    decode(version_id, p);
    decode(error_message, p);
    decode(marker_version_id, p);
    decode(http_status, p);
    decode(error, p);
    decode(delete_marker, p);
    DECODE_FINISH(p);
  }
};
WRITE_CLASS_ENCODER(delete_multi_obj_entry)

struct delete_multi_obj_op_meta {
  uint32_t num_ok = 0;
  uint32_t num_err = 0;
  std::vector<delete_multi_obj_entry> objects;

  void encode(bufferlist &bl) const {
    ENCODE_START(1, 1, bl);
    encode(num_ok, bl);
    encode(num_err, bl);
    encode(objects, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::const_iterator &p) {
    DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, p);
    decode(num_ok, p);
    decode(num_err, p);
    decode(objects, p);
    DECODE_FINISH(p);
  }
};
WRITE_CLASS_ENCODER(delete_multi_obj_op_meta)

struct rgw_log_entry {

  using headers_map = boost::container::flat_map<std::string, std::string>;
  using Clock = req_state::Clock;

  struct KeystoneRole {
    std::string name;
    std::string domain_id;
    std::string domain_name;

    KeystoneRole() = default;

    KeystoneRole(const std::string& role_name,
                 const std::string& role_domain_id = "",
                 const std::string& role_domain_name = "")
      : name(role_name), domain_id(role_domain_id), domain_name(role_domain_name) {}

    void encode(bufferlist& bl) const {
      ENCODE_START(1, 1, bl);
      encode(name, bl);
      encode(domain_id, bl);
      encode(domain_name, bl);
      ENCODE_FINISH(bl);
    }

    void decode(bufferlist::const_iterator& p) {
      DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, p);
      decode(name, p);
      decode(domain_id, p);
      decode(domain_name, p);
      DECODE_FINISH(p);
    }

    bool is_valid() const {
      return !name.empty();
    }
  };

  rgw_owner object_owner;
  rgw_owner bucket_owner;
  std::string bucket;
  Clock::time_point time;
  std::string remote_addr;
  std::string user;
  rgw_obj_key obj;
  std::string op;
  std::string uri;
  std::string http_status;
  std::string error_code;
  uint64_t bytes_sent = 0;
  uint64_t bytes_received = 0;
  uint64_t obj_size = 0;
  Clock::duration total_time{};
  std::string user_agent;
  std::string referrer;
  std::string bucket_id;
  headers_map x_headers;
  std::string trans_id;
  std::vector<std::string> token_claims;
  uint32_t identity_type = TYPE_NONE;
  std::string access_key_id;
  std::string subuser;
  bool temp_url {false};
  delete_multi_obj_op_meta delete_multi_obj_meta;
  rgw_account_id account_id;
  std::string role_id;

  /* Keystone identity fields (version 16)
   * Version bump required to add complete Keystone authentication context for ops logs.
   * Alternatives considered:
   * - Encode as JSON string in existing field: loses structure, harder to parse
   * - Separate log file: harder to correlate, breaks existing log analysis tools
   * - External metadata service: additional infrastructure, latency, complexity
   * Chosen: Structured fields in rgw_log_entry provides integration with existing
   * ops log infrastructure while maintaining backward-compatible decode. */
  std::string keystone_project_id;
  std::string keystone_project_name;
  std::string keystone_project_domain_id;
  std::string keystone_project_domain_name;
  
  // User information  
  std::string keystone_user_id;
  std::string keystone_user_name;
  std::string keystone_user_domain_id;
  std::string keystone_user_domain_name;
  
  // Application credential information
  std::string keystone_app_credential_id;
  std::string keystone_app_credential_name;
  bool keystone_app_credential_restricted = false;
  
  // Roles (vector placed at end to minimize padding)
  std::vector<KeystoneRole> keystone_roles;

  void encode(bufferlist &bl) const {
    ENCODE_START(16, 5, bl);
    // old object/bucket owner ids, encoded in full in v8
    std::string empty_owner_id;
    encode(empty_owner_id, bl);
    encode(empty_owner_id, bl);

    encode(bucket, bl);
    encode(time, bl);
    encode(remote_addr, bl);
    encode(user, bl);
    encode(obj.name, bl);
    encode(op, bl);
    encode(uri, bl);
    encode(http_status, bl);
    encode(error_code, bl);
    encode(bytes_sent, bl);
    encode(obj_size, bl);
    encode(total_time, bl);
    encode(user_agent, bl);
    encode(referrer, bl);
    encode(bytes_received, bl);
    encode(bucket_id, bl);
    encode(obj, bl);
    // transparently converted from rgw_user to rgw_owner
    ceph::converted_variant::encode(object_owner, bl);
    ceph::converted_variant::encode(bucket_owner, bl);
    encode(x_headers, bl);
    encode(trans_id, bl);
    encode(token_claims, bl);
    encode(identity_type,bl);
    encode(access_key_id, bl);
    encode(subuser, bl);
    encode(temp_url, bl);
    encode(delete_multi_obj_meta, bl);
    encode(account_id, bl);
    encode(role_id, bl);
    
    // Version 16 fields - Keystone identity data (maintain wire format order)
    encode(keystone_project_id, bl);
    encode(keystone_project_name, bl);
    encode(keystone_project_domain_id, bl);
    encode(keystone_project_domain_name, bl);
    encode(keystone_user_id, bl);
    encode(keystone_user_name, bl);
    encode(keystone_user_domain_id, bl);
    encode(keystone_user_domain_name, bl);
    encode(keystone_roles, bl);
    encode(keystone_app_credential_id, bl);
    encode(keystone_app_credential_name, bl);
    encode(keystone_app_credential_restricted, bl);
    
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::const_iterator &p) {
    DECODE_START_LEGACY_COMPAT_LEN(16, 5, 5, p);
    std::string object_owner_id;
    std::string bucket_owner_id;
    decode(object_owner_id, p);
    if (struct_v > 3)
      decode(bucket_owner_id, p);
    decode(bucket, p);
    decode(time, p);
    decode(remote_addr, p);
    decode(user, p);
    decode(obj.name, p);
    decode(op, p);
    decode(uri, p);
    decode(http_status, p);
    decode(error_code, p);
    decode(bytes_sent, p);
    decode(obj_size, p);
    decode(total_time, p);
    decode(user_agent, p);
    decode(referrer, p);
    if (struct_v >= 2)
      decode(bytes_received, p);
    else
      bytes_received = 0;

    if (struct_v >= 3) {
      if (struct_v <= 5) {
        uint64_t id;
        decode(id, p);
        char buf[32];
        snprintf(buf, sizeof(buf), "%" PRIu64, id);
        bucket_id = buf;
      } else {
        decode(bucket_id, p);
      }
    } else {
      bucket_id = "";
    }
    if (struct_v >= 7) {
      decode(obj, p);
    }
    if (struct_v >= 8) {
      // transparently converted from rgw_user to rgw_owner
      ceph::converted_variant::decode(object_owner, p);
      ceph::converted_variant::decode(bucket_owner, p);
    } else {
      object_owner = parse_owner(object_owner_id);
      bucket_owner = parse_owner(bucket_owner_id);
    }
    if (struct_v >= 9) {
      decode(x_headers, p);
    }
    if (struct_v >= 10) {
      decode(trans_id, p);
    }
    if (struct_v >= 11) {
      decode(token_claims, p);
    }
    if (struct_v >= 12) {
      decode(identity_type, p);
    }
    if (struct_v >= 13) {
      decode(access_key_id, p);
      decode(subuser, p);
      decode(temp_url, p);
    }
    if (struct_v >= 14) {
      decode(delete_multi_obj_meta, p);
    }
    if (struct_v >= 15) {
      decode(account_id, p);
      decode(role_id, p);
    }
    if (struct_v >= 16) {
      decode(keystone_project_id, p);
      decode(keystone_project_name, p);
      decode(keystone_project_domain_id, p);
      decode(keystone_project_domain_name, p);
      decode(keystone_user_id, p);
      decode(keystone_user_name, p);
      decode(keystone_user_domain_id, p);
      decode(keystone_user_domain_name, p);
      decode(keystone_roles, p);
      decode(keystone_app_credential_id, p);
      decode(keystone_app_credential_name, p);
      decode(keystone_app_credential_restricted, p);
    }
    DECODE_FINISH(p);
  }
  void dump(ceph::Formatter *f) const;
  static std::list<rgw_log_entry> generate_test_instances();
  
  // Utility methods for Keystone field management
  bool has_keystone_data() const {
    return !keystone_project_id.empty() || !keystone_user_id.empty() ||
           !keystone_roles.empty() || !keystone_app_credential_id.empty() ||
           !keystone_app_credential_name.empty();
  }
  
  void clear_keystone_data() {
    keystone_project_id.clear();
    keystone_project_name.clear();
    keystone_project_domain_id.clear();
    keystone_project_domain_name.clear();
    keystone_user_id.clear();
    keystone_user_name.clear();
    keystone_user_domain_id.clear();
    keystone_user_domain_name.clear();
    keystone_app_credential_id.clear();
    keystone_app_credential_name.clear();
    keystone_app_credential_restricted = false;
    keystone_roles.clear();
  }
};
WRITE_CLASS_ENCODER(rgw_log_entry::KeystoneRole)
WRITE_CLASS_ENCODER(rgw_log_entry)

class OpsLogSink {
public:
  virtual int log(req_state* s, struct rgw_log_entry& entry) = 0;
  virtual ~OpsLogSink() = default;
};

class OpsLogManifold: public OpsLogSink {
  std::vector<OpsLogSink*> sinks;
public:
  ~OpsLogManifold() override;
  void add_sink(OpsLogSink* sink);
  int log(req_state* s, struct rgw_log_entry& entry) override;
};

class JsonOpsLogSink : public OpsLogSink {
  ceph::Formatter *formatter;
  ceph::mutex lock = ceph::make_mutex("JsonOpsLogSink");

  void formatter_to_bl(bufferlist& bl);
protected:
  virtual int log_json(req_state* s, bufferlist& bl) = 0;
public:
  JsonOpsLogSink();
  ~JsonOpsLogSink() override;
  int log(req_state* s, struct rgw_log_entry& entry) override;
};

class OpsLogFile : public JsonOpsLogSink, public Thread, public DoutPrefixProvider {
  CephContext* cct;
  ceph::mutex mutex = ceph::make_mutex("OpsLogFile");
  std::vector<bufferlist> log_buffer;
  std::vector<bufferlist> flush_buffer;
  ceph::condition_variable cond;
  std::ofstream file;
  bool stopped;
  uint64_t data_size;
  uint64_t max_data_size;
  std::string path;
  std::atomic_bool need_reopen;

  void flush();
protected:
  int log_json(req_state* s, bufferlist& bl) override;
  void *entry() override;
public:
  OpsLogFile(CephContext* cct, std::string& path, uint64_t max_data_size);
  ~OpsLogFile() override;
  CephContext *get_cct() const override { return cct; }
  unsigned get_subsys() const override;
  std::ostream& gen_prefix(std::ostream& out) const override { return out << "rgw OpsLogFile: "; }
  void reopen();
  void start();
  void stop();
};

class OpsLogSocket : public OutputDataSocket, public JsonOpsLogSink {
protected:
  int log_json(req_state* s, bufferlist& bl) override;
  void init_connection(bufferlist& bl) override;

public:
  OpsLogSocket(CephContext *cct, uint64_t _backlog);
};

class OpsLogRados : public OpsLogSink {
  // main()'s driver pointer as a reference, possibly modified by RGWRealmReloader
  rgw::sal::Driver* const& driver;

public:
  OpsLogRados(rgw::sal::Driver* const& driver);
  int log(req_state* s, struct rgw_log_entry& entry) override;
};

class RGWREST;

int rgw_log_op(RGWREST* const rest, struct req_state* s,
	             const RGWOp* op, OpsLogSink* olog);
void rgw_log_usage_init(CephContext* cct, rgw::sal::Driver* driver);
void rgw_log_usage_finalize();
void rgw_format_ops_log_entry(struct rgw_log_entry& entry,
			      ceph::Formatter *formatter);
