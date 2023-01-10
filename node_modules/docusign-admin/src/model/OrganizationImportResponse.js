/**
 * DocuSign Admin API
 * An API for an organization administrator to manage organizations, accounts and users
 *
 * OpenAPI spec version: v2.1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/OrganizationImportResponseErrorRollup', 'model/OrganizationImportResponseRequestor', 'model/OrganizationImportResponseWarningRollup'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrganizationImportResponseErrorRollup'), require('./OrganizationImportResponseRequestor'), require('./OrganizationImportResponseWarningRollup'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationImportResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationImportResponseErrorRollup, root.DocusignAdmin.OrganizationImportResponseRequestor, root.DocusignAdmin.OrganizationImportResponseWarningRollup);
  }
}(this, function(ApiClient, OrganizationImportResponseErrorRollup, OrganizationImportResponseRequestor, OrganizationImportResponseWarningRollup) {
  'use strict';


  /**
   * The OrganizationImportResponse model module.
   * @module model/OrganizationImportResponse
   */

  /**
   * Constructs a new <code>OrganizationImportResponse</code>.
   * @alias module:model/OrganizationImportResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationImportResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationImportResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationImportResponse} The populated <code>OrganizationImportResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('type')) {
        obj['type'] = ApiClient.convertToType(data['type'], 'String');
      }
      if (data.hasOwnProperty('requestor')) {
        obj['requestor'] = OrganizationImportResponseRequestor.constructFromObject(data['requestor']);
      }
      if (data.hasOwnProperty('created')) {
        obj['created'] = ApiClient.convertToType(data['created'], 'Date');
      }
      if (data.hasOwnProperty('last_modified')) {
        obj['last_modified'] = ApiClient.convertToType(data['last_modified'], 'Date');
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
      if (data.hasOwnProperty('user_count')) {
        obj['user_count'] = ApiClient.convertToType(data['user_count'], 'Number');
      }
      if (data.hasOwnProperty('processed_user_count')) {
        obj['processed_user_count'] = ApiClient.convertToType(data['processed_user_count'], 'Number');
      }
      if (data.hasOwnProperty('added_user_count')) {
        obj['added_user_count'] = ApiClient.convertToType(data['added_user_count'], 'Number');
      }
      if (data.hasOwnProperty('updated_user_count')) {
        obj['updated_user_count'] = ApiClient.convertToType(data['updated_user_count'], 'Number');
      }
      if (data.hasOwnProperty('closed_user_count')) {
        obj['closed_user_count'] = ApiClient.convertToType(data['closed_user_count'], 'Number');
      }
      if (data.hasOwnProperty('no_action_required_user_count')) {
        obj['no_action_required_user_count'] = ApiClient.convertToType(data['no_action_required_user_count'], 'Number');
      }
      if (data.hasOwnProperty('error_count')) {
        obj['error_count'] = ApiClient.convertToType(data['error_count'], 'Number');
      }
      if (data.hasOwnProperty('warning_count')) {
        obj['warning_count'] = ApiClient.convertToType(data['warning_count'], 'Number');
      }
      if (data.hasOwnProperty('invalid_column_headers')) {
        obj['invalid_column_headers'] = ApiClient.convertToType(data['invalid_column_headers'], 'String');
      }
      if (data.hasOwnProperty('imports_not_found_or_not_available_for_accounts')) {
        obj['imports_not_found_or_not_available_for_accounts'] = ApiClient.convertToType(data['imports_not_found_or_not_available_for_accounts'], 'String');
      }
      if (data.hasOwnProperty('imports_failed_for_accounts')) {
        obj['imports_failed_for_accounts'] = ApiClient.convertToType(data['imports_failed_for_accounts'], 'String');
      }
      if (data.hasOwnProperty('imports_timed_out_for_accounts')) {
        obj['imports_timed_out_for_accounts'] = ApiClient.convertToType(data['imports_timed_out_for_accounts'], 'String');
      }
      if (data.hasOwnProperty('imports_not_found_or_not_available_for_sites')) {
        obj['imports_not_found_or_not_available_for_sites'] = ApiClient.convertToType(data['imports_not_found_or_not_available_for_sites'], 'String');
      }
      if (data.hasOwnProperty('imports_failed_for_sites')) {
        obj['imports_failed_for_sites'] = ApiClient.convertToType(data['imports_failed_for_sites'], 'String');
      }
      if (data.hasOwnProperty('imports_timed_out_for_sites')) {
        obj['imports_timed_out_for_sites'] = ApiClient.convertToType(data['imports_timed_out_for_sites'], 'String');
      }
      if (data.hasOwnProperty('file_level_error_rollups')) {
        obj['file_level_error_rollups'] = ApiClient.convertToType(data['file_level_error_rollups'], [OrganizationImportResponseErrorRollup]);
      }
      if (data.hasOwnProperty('user_level_error_rollups')) {
        obj['user_level_error_rollups'] = ApiClient.convertToType(data['user_level_error_rollups'], [OrganizationImportResponseErrorRollup]);
      }
      if (data.hasOwnProperty('user_level_warning_rollups')) {
        obj['user_level_warning_rollups'] = ApiClient.convertToType(data['user_level_warning_rollups'], [OrganizationImportResponseWarningRollup]);
      }
      if (data.hasOwnProperty('has_csv_results')) {
        obj['has_csv_results'] = ApiClient.convertToType(data['has_csv_results'], 'Boolean');
      }
      if (data.hasOwnProperty('results_uri')) {
        obj['results_uri'] = ApiClient.convertToType(data['results_uri'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {String} type
   */
  exports.prototype['type'] = undefined;
  /**
   * @member {module:model/OrganizationImportResponseRequestor} requestor
   */
  exports.prototype['requestor'] = undefined;
  /**
   * @member {Date} created
   */
  exports.prototype['created'] = undefined;
  /**
   * @member {Date} last_modified
   */
  exports.prototype['last_modified'] = undefined;
  /**
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
  /**
   * @member {Number} user_count
   */
  exports.prototype['user_count'] = undefined;
  /**
   * @member {Number} processed_user_count
   */
  exports.prototype['processed_user_count'] = undefined;
  /**
   * @member {Number} added_user_count
   */
  exports.prototype['added_user_count'] = undefined;
  /**
   * @member {Number} updated_user_count
   */
  exports.prototype['updated_user_count'] = undefined;
  /**
   * @member {Number} closed_user_count
   */
  exports.prototype['closed_user_count'] = undefined;
  /**
   * @member {Number} no_action_required_user_count
   */
  exports.prototype['no_action_required_user_count'] = undefined;
  /**
   * @member {Number} error_count
   */
  exports.prototype['error_count'] = undefined;
  /**
   * @member {Number} warning_count
   */
  exports.prototype['warning_count'] = undefined;
  /**
   * @member {String} invalid_column_headers
   */
  exports.prototype['invalid_column_headers'] = undefined;
  /**
   * @member {String} imports_not_found_or_not_available_for_accounts
   */
  exports.prototype['imports_not_found_or_not_available_for_accounts'] = undefined;
  /**
   * @member {String} imports_failed_for_accounts
   */
  exports.prototype['imports_failed_for_accounts'] = undefined;
  /**
   * @member {String} imports_timed_out_for_accounts
   */
  exports.prototype['imports_timed_out_for_accounts'] = undefined;
  /**
   * @member {String} imports_not_found_or_not_available_for_sites
   */
  exports.prototype['imports_not_found_or_not_available_for_sites'] = undefined;
  /**
   * @member {String} imports_failed_for_sites
   */
  exports.prototype['imports_failed_for_sites'] = undefined;
  /**
   * @member {String} imports_timed_out_for_sites
   */
  exports.prototype['imports_timed_out_for_sites'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationImportResponseErrorRollup>} file_level_error_rollups
   */
  exports.prototype['file_level_error_rollups'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationImportResponseErrorRollup>} user_level_error_rollups
   */
  exports.prototype['user_level_error_rollups'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationImportResponseWarningRollup>} user_level_warning_rollups
   */
  exports.prototype['user_level_warning_rollups'] = undefined;
  /**
   * @member {Boolean} has_csv_results
   */
  exports.prototype['has_csv_results'] = undefined;
  /**
   * @member {String} results_uri
   */
  exports.prototype['results_uri'] = undefined;



  return exports;
}));


