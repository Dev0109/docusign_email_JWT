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
    define(['ApiClient', 'model/MembershipResponse', 'model/UserIdentityResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./MembershipResponse'), require('./UserIdentityResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UserDrilldownResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.MembershipResponse, root.DocusignAdmin.UserIdentityResponse);
  }
}(this, function(ApiClient, MembershipResponse, UserIdentityResponse) {
  'use strict';


  /**
   * The UserDrilldownResponse model module.
   * @module model/UserDrilldownResponse
   */

  /**
   * Constructs a new <code>UserDrilldownResponse</code>.
   * @alias module:model/UserDrilldownResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>UserDrilldownResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UserDrilldownResponse} obj Optional instance to populate.
   * @return {module:model/UserDrilldownResponse} The populated <code>UserDrilldownResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('site_id')) {
        obj['site_id'] = ApiClient.convertToType(data['site_id'], 'Number');
      }
      if (data.hasOwnProperty('site_name')) {
        obj['site_name'] = ApiClient.convertToType(data['site_name'], 'String');
      }
      if (data.hasOwnProperty('user_name')) {
        obj['user_name'] = ApiClient.convertToType(data['user_name'], 'String');
      }
      if (data.hasOwnProperty('first_name')) {
        obj['first_name'] = ApiClient.convertToType(data['first_name'], 'String');
      }
      if (data.hasOwnProperty('last_name')) {
        obj['last_name'] = ApiClient.convertToType(data['last_name'], 'String');
      }
      if (data.hasOwnProperty('user_status')) {
        obj['user_status'] = ApiClient.convertToType(data['user_status'], 'String');
      }
      if (data.hasOwnProperty('default_account_id')) {
        obj['default_account_id'] = ApiClient.convertToType(data['default_account_id'], 'String');
      }
      if (data.hasOwnProperty('default_account_name')) {
        obj['default_account_name'] = ApiClient.convertToType(data['default_account_name'], 'String');
      }
      if (data.hasOwnProperty('language_culture')) {
        obj['language_culture'] = ApiClient.convertToType(data['language_culture'], 'String');
      }
      if (data.hasOwnProperty('selected_languages')) {
        obj['selected_languages'] = ApiClient.convertToType(data['selected_languages'], 'String');
      }
      if (data.hasOwnProperty('federated_status')) {
        obj['federated_status'] = ApiClient.convertToType(data['federated_status'], 'String');
      }
      if (data.hasOwnProperty('is_organization_admin')) {
        obj['is_organization_admin'] = ApiClient.convertToType(data['is_organization_admin'], 'Boolean');
      }
      if (data.hasOwnProperty('created_on')) {
        obj['created_on'] = ApiClient.convertToType(data['created_on'], 'Date');
      }
      if (data.hasOwnProperty('last_login')) {
        obj['last_login'] = ApiClient.convertToType(data['last_login'], 'Date');
      }
      if (data.hasOwnProperty('memberships')) {
        obj['memberships'] = ApiClient.convertToType(data['memberships'], [MembershipResponse]);
      }
      if (data.hasOwnProperty('identities')) {
        obj['identities'] = ApiClient.convertToType(data['identities'], [UserIdentityResponse]);
      }
      if (data.hasOwnProperty('device_verification_enabled')) {
        obj['device_verification_enabled'] = ApiClient.convertToType(data['device_verification_enabled'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {Number} site_id
   */
  exports.prototype['site_id'] = undefined;
  /**
   * @member {String} site_name
   */
  exports.prototype['site_name'] = undefined;
  /**
   * @member {String} user_name
   */
  exports.prototype['user_name'] = undefined;
  /**
   * @member {String} first_name
   */
  exports.prototype['first_name'] = undefined;
  /**
   * @member {String} last_name
   */
  exports.prototype['last_name'] = undefined;
  /**
   * @member {String} user_status
   */
  exports.prototype['user_status'] = undefined;
  /**
   * @member {String} default_account_id
   */
  exports.prototype['default_account_id'] = undefined;
  /**
   * @member {String} default_account_name
   */
  exports.prototype['default_account_name'] = undefined;
  /**
   * @member {String} language_culture
   */
  exports.prototype['language_culture'] = undefined;
  /**
   * @member {String} selected_languages
   */
  exports.prototype['selected_languages'] = undefined;
  /**
   * @member {String} federated_status
   */
  exports.prototype['federated_status'] = undefined;
  /**
   * @member {Boolean} is_organization_admin
   */
  exports.prototype['is_organization_admin'] = undefined;
  /**
   * @member {Date} created_on
   */
  exports.prototype['created_on'] = undefined;
  /**
   * @member {Date} last_login
   */
  exports.prototype['last_login'] = undefined;
  /**
   * @member {Array.<module:model/MembershipResponse>} memberships
   */
  exports.prototype['memberships'] = undefined;
  /**
   * @member {Array.<module:model/UserIdentityResponse>} identities
   */
  exports.prototype['identities'] = undefined;
  /**
   * @member {Boolean} device_verification_enabled
   */
  exports.prototype['device_verification_enabled'] = undefined;



  return exports;
}));


