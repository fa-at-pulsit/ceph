// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#pragma once

#include "rgw_keystone.h"
#include "rgw_auth.h"

struct rgw_log_entry;

namespace rgw {
namespace auth {
namespace keystone {

class KeystoneDataExtractor {
public:
  static void extract_keystone_data(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry,
    bool include_keystone_scope
  ) noexcept;

  static void populate_from_auth_info(
    const ::rgw::auth::RemoteApplier::AuthInfo& info,
    rgw_log_entry& entry
  );

private:
  static void extract_project_fields(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry
  ) noexcept;

  static void extract_user_fields(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry
  ) noexcept;

  static void extract_roles_array(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry
  ) noexcept;

  static void extract_application_credential(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry
  ) noexcept;

  static void safe_string_copy(
    const std::string& source,
    std::string& destination
  ) noexcept;
};

} // namespace keystone
} // namespace auth  
} // namespace rgw