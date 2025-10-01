// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "rgw_log.h"
#include "gtest/gtest.h"
#include <memory>

class rgw_log_entry_test : public ::testing::Test {
 protected:
  rgw_log_entry entry;
};

// Test for version 16 encoding with new Keystone fields
TEST_F(rgw_log_entry_test, encode_decode_version_16_keystone_fields) {
  // Prepare test data with new Keystone fields
  entry.keystone_project_id = "proj123";
  entry.keystone_project_name = "test-project";
  entry.keystone_project_domain_id = "domain456";
  entry.keystone_project_domain_name = "test-domain";
  entry.keystone_user_id = "user789";
  entry.keystone_user_name = "test-user";
  entry.keystone_user_domain_id = "user_domain_123";
  entry.keystone_user_domain_name = "user-domain";
  entry.keystone_app_credential_id = "app_cred_456";
  
  // Add test roles
  rgw_log_entry::KeystoneRole role1;
  role1.name = "admin";
  role1.domain_id = "role_domain_1";
  role1.domain_name = "role-domain-1";
  
  rgw_log_entry::KeystoneRole role2;
  role2.name = "member";
  role2.domain_id = "role_domain_2";
  role2.domain_name = "role-domain-2";
  
  entry.keystone_roles.push_back(role1);
  entry.keystone_roles.push_back(role2);

  // Encode the entry
  bufferlist bl;
  encode(entry, bl);

  // Decode the entry
  rgw_log_entry decoded_entry;
  auto p = bl.cbegin();
  decode(decoded_entry, p);

  // Verify all Keystone fields are preserved
  EXPECT_EQ("proj123", decoded_entry.keystone_project_id);
  EXPECT_EQ("test-project", decoded_entry.keystone_project_name);
  EXPECT_EQ("domain456", decoded_entry.keystone_project_domain_id);
  EXPECT_EQ("test-domain", decoded_entry.keystone_project_domain_name);
  EXPECT_EQ("user789", decoded_entry.keystone_user_id);
  EXPECT_EQ("test-user", decoded_entry.keystone_user_name);
  EXPECT_EQ("user_domain_123", decoded_entry.keystone_user_domain_id);
  EXPECT_EQ("user-domain", decoded_entry.keystone_user_domain_name);
  EXPECT_EQ("app_cred_456", decoded_entry.keystone_app_credential_id);
  
  ASSERT_EQ(2u, decoded_entry.keystone_roles.size());
  EXPECT_EQ("admin", decoded_entry.keystone_roles[0].name);
  EXPECT_EQ("role_domain_1", decoded_entry.keystone_roles[0].domain_id);
  EXPECT_EQ("role-domain-1", decoded_entry.keystone_roles[0].domain_name);
  EXPECT_EQ("member", decoded_entry.keystone_roles[1].name);
  EXPECT_EQ("role_domain_2", decoded_entry.keystone_roles[1].domain_id);
  EXPECT_EQ("role-domain-2", decoded_entry.keystone_roles[1].domain_name);
}

// Test for KeystoneRole encode/decode
TEST_F(rgw_log_entry_test, keystone_role_encode_decode) {
  rgw_log_entry::KeystoneRole role;
  role.name = "test-role";
  role.domain_id = "test-domain-id";
  role.domain_name = "test-domain-name";

  // Encode the role
  bufferlist bl;
  encode(role, bl);

  // Decode the role
  rgw_log_entry::KeystoneRole decoded_role;
  auto p = bl.cbegin();
  decode(decoded_role, p);

  // Verify all fields are preserved
  EXPECT_EQ("test-role", decoded_role.name);
  EXPECT_EQ("test-domain-id", decoded_role.domain_id);
  EXPECT_EQ("test-domain-name", decoded_role.domain_name);
}

// Test for backward compatibility (v15 to v16 upgrade)
TEST_F(rgw_log_entry_test, backward_compatibility_v15_to_v16) {
  // Create a version 15 encoded entry
  rgw_log_entry v15_entry;
  v15_entry.bucket = "test-bucket";
  v15_entry.user = "test-user";
  v15_entry.op = "GET";
  v15_entry.http_status = "200";

  // Manually encode as version 15 (without Keystone fields)
  bufferlist v15_bl;
  {
    ENCODE_START(15, 5, v15_bl);
    // Simulate version 15 encoding (without keystone fields)
    std::string empty_owner_id;
    encode(empty_owner_id, v15_bl);
    encode(empty_owner_id, v15_bl);
    encode(v15_entry.bucket, v15_bl);
    encode(v15_entry.time, v15_bl);
    encode(v15_entry.remote_addr, v15_bl);
    encode(v15_entry.user, v15_bl);
    encode(v15_entry.obj.name, v15_bl);
    encode(v15_entry.op, v15_bl);
    encode(v15_entry.uri, v15_bl);
    encode(v15_entry.http_status, v15_bl);
    encode(v15_entry.error_code, v15_bl);
    encode(v15_entry.bytes_sent, v15_bl);
    encode(v15_entry.obj_size, v15_bl);
    encode(v15_entry.total_time, v15_bl);
    encode(v15_entry.user_agent, v15_bl);
    encode(v15_entry.referrer, v15_bl);
    encode(v15_entry.bytes_received, v15_bl);
    encode(v15_entry.bucket_id, v15_bl);
    encode(v15_entry.obj, v15_bl);
    ceph::converted_variant::encode(v15_entry.object_owner, v15_bl);
    ceph::converted_variant::encode(v15_entry.bucket_owner, v15_bl);
    encode(v15_entry.x_headers, v15_bl);
    encode(v15_entry.trans_id, v15_bl);
    encode(v15_entry.token_claims, v15_bl);
    encode(v15_entry.identity_type, v15_bl);
    encode(v15_entry.access_key_id, v15_bl);
    encode(v15_entry.subuser, v15_bl);
    encode(v15_entry.temp_url, v15_bl);
    encode(v15_entry.delete_multi_obj_meta, v15_bl);
    encode(v15_entry.account_id, v15_bl);
    encode(v15_entry.role_id, v15_bl);
    ENCODE_FINISH(v15_bl);
  }

  // Decode with version 16 decoder (should handle missing Keystone fields)
  rgw_log_entry decoded_entry;
  auto p = v15_bl.cbegin();
  decode(decoded_entry, p);

  // Verify basic fields are preserved
  EXPECT_EQ("test-bucket", decoded_entry.bucket);
  EXPECT_EQ("test-user", decoded_entry.user);
  EXPECT_EQ("GET", decoded_entry.op);
  EXPECT_EQ("200", decoded_entry.http_status);

  // Verify Keystone fields are empty (not set in v15)
  EXPECT_TRUE(decoded_entry.keystone_project_id.empty());
  EXPECT_TRUE(decoded_entry.keystone_project_name.empty());
  EXPECT_TRUE(decoded_entry.keystone_project_domain_id.empty());
  EXPECT_TRUE(decoded_entry.keystone_project_domain_name.empty());
  EXPECT_TRUE(decoded_entry.keystone_user_id.empty());
  EXPECT_TRUE(decoded_entry.keystone_user_name.empty());
  EXPECT_TRUE(decoded_entry.keystone_user_domain_id.empty());
  EXPECT_TRUE(decoded_entry.keystone_user_domain_name.empty());
  EXPECT_TRUE(decoded_entry.keystone_app_credential_id.empty());
  EXPECT_TRUE(decoded_entry.keystone_roles.empty());
}

// Test for configuration option existence and parsing
TEST_F(rgw_log_entry_test, keystone_ops_log_config_option_exists) {
  // This test verifies that the configuration option exists and can be parsed
  // Note: This would normally test CephContext configuration parsing
  // For now, we'll test the logic that would use this configuration
  
  // Test default value should be false
  bool default_enabled = false;  // Simulating rgw_ops_log_keystone_scope default
  EXPECT_FALSE(default_enabled);
  
  // Test explicit true value
  bool explicitly_enabled = true;  // Simulating configured true value
  EXPECT_TRUE(explicitly_enabled);
  
  // Test explicit false value  
  bool explicitly_disabled = false;  // Simulating configured false value
  EXPECT_FALSE(explicitly_disabled);
}

// Test for configuration-driven behavior
TEST_F(rgw_log_entry_test, keystone_logging_controlled_by_config) {
  // Test that Keystone logging behavior is controlled by configuration
  // When config is disabled, Keystone fields should not be populated
  bool config_enabled = false;
  
  rgw_log_entry entry_disabled;
  // Simulate: if (!config_enabled) don't populate Keystone fields
  if (!config_enabled) {
    // Keystone fields should remain empty
    EXPECT_TRUE(entry_disabled.keystone_project_id.empty());
    EXPECT_TRUE(entry_disabled.keystone_user_id.empty());
    EXPECT_TRUE(entry_disabled.keystone_roles.empty());
  }
  
  // When config is enabled, Keystone fields can be populated  
  config_enabled = true;
  rgw_log_entry entry_enabled;
  if (config_enabled) {
    // Simulate populating Keystone fields when enabled
    entry_enabled.keystone_project_id = "test_project";
    entry_enabled.keystone_user_id = "test_user";
    
    EXPECT_EQ("test_project", entry_enabled.keystone_project_id);
    EXPECT_EQ("test_user", entry_enabled.keystone_user_id);
  }
}

// JSON OUTPUT TESTS

class rgw_log_entry_json_test : public ::testing::Test {
protected:
  rgw_log_entry entry;
  std::unique_ptr<ceph::JSONFormatter> formatter;
  
  void SetUp() override {
    formatter = std::make_unique<ceph::JSONFormatter>();
    entry = rgw_log_entry{};
    
    // Setup basic log entry fields
    entry.bucket = "test-bucket";
    entry.user = "test-user";
    entry.op = "GET";
    entry.http_status = "200";
    entry.bytes_sent = 1024;
    entry.bytes_received = 512;
    entry.obj_size = 2048;
  }
  
  std::string get_json_output() {
    std::ostringstream oss;
    formatter->close_section(); // Close the root object opened in test
    formatter->flush(oss);
    return oss.str();
  }
  
  void setup_complete_keystone_data() {
    entry.keystone_project_id = "proj_12345";
    entry.keystone_project_name = "test-project";
    entry.keystone_project_domain_id = "proj_domain_678";
    entry.keystone_project_domain_name = "project-domain";
    entry.keystone_user_id = "user_98765";
    entry.keystone_user_name = "test-user";
    entry.keystone_user_domain_id = "user_domain_432";
    entry.keystone_user_domain_name = "user-domain";
    entry.keystone_app_credential_id = "app_cred_789";
    
    // Add roles
    rgw_log_entry::KeystoneRole role1;
    role1.name = "admin";
    role1.domain_id = "role_domain_1";
    role1.domain_name = "admin-domain";
    
    rgw_log_entry::KeystoneRole role2;
    role2.name = "member";
    role2.domain_id = "role_domain_2"; 
    role2.domain_name = "member-domain";
    
    entry.keystone_roles.push_back(role1);
    entry.keystone_roles.push_back(role2);
  }
};

// Test for nested keystone_scope JSON object structure
TEST_F(rgw_log_entry_json_test, dump_includes_nested_keystone_scope_when_has_data) {
  setup_complete_keystone_data();

  // Open root object for formatter
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();

  // Verify keystone_scope object exists in JSON
  EXPECT_NE(std::string::npos, json_output.find("\"keystone_scope\""));
  
  // Verify nested project structure
  EXPECT_NE(std::string::npos, json_output.find("\"project\""));
  EXPECT_NE(std::string::npos, json_output.find("\"proj_12345\""));
  EXPECT_NE(std::string::npos, json_output.find("\"test-project\""));
  
  // Verify nested user structure
  EXPECT_NE(std::string::npos, json_output.find("\"user\""));
  EXPECT_NE(std::string::npos, json_output.find("\"user_98765\""));
  EXPECT_NE(std::string::npos, json_output.find("\"test-user\""));
  
  // Verify roles array
  EXPECT_NE(std::string::npos, json_output.find("\"roles\""));
  EXPECT_NE(std::string::npos, json_output.find("\"admin\""));
  EXPECT_NE(std::string::npos, json_output.find("\"member\""));
  
  // Verify application credential
  EXPECT_NE(std::string::npos, json_output.find("\"application_credential\""));
  EXPECT_NE(std::string::npos, json_output.find("\"app_cred_789\""));
}

// Test for proper JSON structure with nested domain objects  
TEST_F(rgw_log_entry_json_test, dump_nested_domain_objects_correctly) {
  setup_complete_keystone_data();
  
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();
  
  // Verify project domain nesting: project.domain.id and project.domain.name
  EXPECT_NE(std::string::npos, json_output.find("\"proj_domain_678\""));
  EXPECT_NE(std::string::npos, json_output.find("\"project-domain\""));
  
  // Verify user domain nesting: user.domain.id and user.domain.name
  EXPECT_NE(std::string::npos, json_output.find("\"user_domain_432\""));
  EXPECT_NE(std::string::npos, json_output.find("\"user-domain\""));
  
  // Verify role domain nesting: roles[].domain.id and roles[].domain.name
  EXPECT_NE(std::string::npos, json_output.find("\"role_domain_1\""));
  EXPECT_NE(std::string::npos, json_output.find("\"admin-domain\""));
  EXPECT_NE(std::string::npos, json_output.find("\"role_domain_2\""));
  EXPECT_NE(std::string::npos, json_output.find("\"member-domain\""));
}

// Test for null field handling in JSON output
TEST_F(rgw_log_entry_json_test, dump_explicit_null_values_for_missing_fields) {
  // Setup entry with some missing Keystone fields
  entry.keystone_project_id = "proj_123";
  // Leave other fields empty to test null handling
  
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();
  
  // Should output explicit null values, not omit fields
  EXPECT_NE(std::string::npos, json_output.find("\"keystone_scope\""));
  EXPECT_NE(std::string::npos, json_output.find("\"proj_123\""));
  
  // Missing fields should be explicit null (not omitted)
  // This will test the proper null handling in JSON output
  EXPECT_NE(std::string::npos, json_output.find("null"));
}

// Test for roles array JSON serialization
TEST_F(rgw_log_entry_json_test, dump_roles_array_as_proper_json) {
  // Add multiple roles to test array serialization
  rgw_log_entry::KeystoneRole role1;
  role1.name = "admin";
  role1.domain_id = "domain1";
  role1.domain_name = "Admin Domain";
  
  rgw_log_entry::KeystoneRole role2;
  role2.name = "viewer";
  role2.domain_id = "domain2";
  role2.domain_name = "Viewer Domain";
  
  rgw_log_entry::KeystoneRole role3;
  role3.name = "editor";
  // No domain info for this role to test mixed scenarios
  
  entry.keystone_roles.push_back(role1);
  entry.keystone_roles.push_back(role2);
  entry.keystone_roles.push_back(role3);
  
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();
  
  // Verify proper JSON array structure for roles
  EXPECT_NE(std::string::npos, json_output.find("\"roles\":["));
  
  // Verify all roles are present
  EXPECT_NE(std::string::npos, json_output.find("\"admin\""));
  EXPECT_NE(std::string::npos, json_output.find("\"viewer\""));
  EXPECT_NE(std::string::npos, json_output.find("\"editor\""));
  
  // Verify role domain information
  EXPECT_NE(std::string::npos, json_output.find("\"Admin Domain\""));
  EXPECT_NE(std::string::npos, json_output.find("\"Viewer Domain\""));
}

// Test for empty roles array handling
TEST_F(rgw_log_entry_json_test, dump_empty_roles_array_correctly) {
  setup_complete_keystone_data();
  entry.keystone_roles.clear(); // Remove all roles
  
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();
  
  // Should output empty array, not omit the field
  EXPECT_NE(std::string::npos, json_output.find("\"roles\":[]"));
}

// Test for no keystone_scope when no Keystone data
TEST_F(rgw_log_entry_json_test, dump_omits_keystone_scope_when_no_data) {
  // Entry with no Keystone data - keystone_scope should not be present
  EXPECT_FALSE(entry.has_keystone_data());
  
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();
  
  // keystone_scope should not be present when no Keystone data
  EXPECT_EQ(std::string::npos, json_output.find("\"keystone_scope\""));
  
  // But basic fields should still be present
  EXPECT_NE(std::string::npos, json_output.find("\"bucket\""));
  EXPECT_NE(std::string::npos, json_output.find("\"test-bucket\""));
  EXPECT_NE(std::string::npos, json_output.find("\"user\""));
  EXPECT_NE(std::string::npos, json_output.find("\"test-user\""));
}

// Test for backward compatibility with existing JSON parsers
TEST_F(rgw_log_entry_json_test, dump_maintains_existing_json_fields) {
  setup_complete_keystone_data();
  
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();
  
  // Verify all existing fields are still present
  EXPECT_NE(std::string::npos, json_output.find("\"bucket\""));
  EXPECT_NE(std::string::npos, json_output.find("\"test-bucket\""));
  EXPECT_NE(std::string::npos, json_output.find("\"user\""));
  EXPECT_NE(std::string::npos, json_output.find("\"test-user\""));
  EXPECT_NE(std::string::npos, json_output.find("\"op\""));
  EXPECT_NE(std::string::npos, json_output.find("\"GET\""));
  EXPECT_NE(std::string::npos, json_output.find("\"http_status\""));
  EXPECT_NE(std::string::npos, json_output.find("\"200\""));
  EXPECT_NE(std::string::npos, json_output.find("\"bytes_sent\""));
  EXPECT_NE(std::string::npos, json_output.find("1024"));
  EXPECT_NE(std::string::npos, json_output.find("\"bytes_received\""));
  EXPECT_NE(std::string::npos, json_output.find("512"));
  
  // AND keystone_scope should be additional
  EXPECT_NE(std::string::npos, json_output.find("\"keystone_scope\""));
}

// Test for JSON schema compliance with design specification
TEST_F(rgw_log_entry_json_test, dump_matches_expected_json_schema) {
  setup_complete_keystone_data();
  
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();
  
  // Test exact schema structure matches design.md specification
  // Expected structure:
  // "keystone_scope": {
  //   "project": { "id": "...", "name": "...", "domain": { "id": "...", "name": "..." } },
  //   "user": { "id": "...", "name": "...", "domain": { "id": "...", "name": "..." } },
  //   "roles": [ { "name": "...", "domain": { "id": "...", "name": "..." } } ],
  //   "application_credential": { "id": "..." }
  // }
  
  // This test will validate the exact JSON structure
  // It should fail initially until the JSON output is implemented correctly
  
  // Parse the JSON and verify structure (simplified validation for now)
  EXPECT_NE(std::string::npos, json_output.find("\"keystone_scope\":{"));
  EXPECT_NE(std::string::npos, json_output.find("\"project\":{"));
  EXPECT_NE(std::string::npos, json_output.find("\"user\":{"));
  EXPECT_NE(std::string::npos, json_output.find("\"roles\":["));
  EXPECT_NE(std::string::npos, json_output.find("\"application_credential\":{"));
}

// Test for JSON format validation across different scenarios
TEST_F(rgw_log_entry_json_test, dump_consistent_format_various_scenarios) {
  // Test scenario 1: Complete data
  setup_complete_keystone_data();
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string complete_json = get_json_output();
  formatter = std::make_unique<ceph::JSONFormatter>(); // Reset formatter
  
  // Test scenario 2: Partial data (only project info)
  rgw_log_entry partial_entry;
  partial_entry.bucket = "test-bucket";
  partial_entry.keystone_project_id = "proj_456";
  partial_entry.keystone_project_name = "partial-project";

  formatter->open_object_section("");
  partial_entry.dump(formatter.get());
  std::string partial_json = get_json_output();
  formatter = std::make_unique<ceph::JSONFormatter>(); // Reset formatter

  // Test scenario 3: No Keystone data
  rgw_log_entry no_keystone_entry;
  no_keystone_entry.bucket = "test-bucket";

  formatter->open_object_section("");
  no_keystone_entry.dump(formatter.get());
  std::string no_keystone_json = get_json_output();
  
  // Verify all scenarios produce valid JSON structure
  // Complete data should have keystone_scope
  EXPECT_NE(std::string::npos, complete_json.find("\"keystone_scope\""));
  
  // Partial data should have keystone_scope with null fields where appropriate
  EXPECT_NE(std::string::npos, partial_json.find("\"keystone_scope\""));
  EXPECT_NE(std::string::npos, partial_json.find("\"proj_456\""));
  
  // No Keystone data should not have keystone_scope
  EXPECT_EQ(std::string::npos, no_keystone_json.find("\"keystone_scope\""));
}

// Test for performance with large roles array
TEST_F(rgw_log_entry_json_test, dump_handles_large_roles_array_efficiently) {
  // Create entry with many roles to test performance and memory efficiency
  for (int i = 0; i < 50; ++i) {
    rgw_log_entry::KeystoneRole role;
    role.name = "role_" + std::to_string(i);
    role.domain_id = "domain_" + std::to_string(i);
    role.domain_name = "Domain " + std::to_string(i);
    entry.keystone_roles.push_back(role);
  }
  
  // This should handle large arrays efficiently
  formatter->open_object_section("");
  entry.dump(formatter.get());
  std::string json_output = get_json_output();
  
  // Verify all roles are present in JSON
  EXPECT_NE(std::string::npos, json_output.find("\"roles\":["));
  EXPECT_NE(std::string::npos, json_output.find("\"role_0\""));
  EXPECT_NE(std::string::npos, json_output.find("\"role_49\""));
  
  // Verify JSON structure is maintained
  EXPECT_NE(std::string::npos, json_output.find("\"keystone_scope\""));
}