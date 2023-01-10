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
    define(['ApiClient', 'model/MemberGroupResponse', 'model/PermissionProfileResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./MemberGroupResponse'), require('./PermissionProfileResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.NewUserResponseAccountProperties = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.MemberGroupResponse, root.DocusignAdmin.PermissionProfileResponse);
  }
}(this, function(ApiClient, MemberGroupResponse, PermissionProfileResponse) {
  'use strict';


  /**
   * The NewUserResponseAccountProperties model module.
   * @module model/NewUserResponseAccountProperties
   */

  /**
   * Constructs a new <code>NewUserResponseAccountProperties</code>.
   * @alias module:model/NewUserResponseAccountProperties
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>NewUserResponseAccountProperties</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/NewUserResponseAccountProperties} obj Optional instance to populate.
   * @return {module:model/NewUserResponseAccountProperties} The populated <code>NewUserResponseAccountProperties</code> instance.
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
      if (data.hasOwnProperty('permission_profile')) {
        obj['permission_profile'] = PermissionProfileResponse.constructFromObject(data['permission_profile']);
      }
      if (data.hasOwnProperty('groups')) {
        obj['groups'] = ApiClient.convertToType(data['groups'], [MemberGroupResponse]);
      }
      if (data.hasOwnProperty('company_name')) {
        obj['company_name'] = ApiClient.convertToType(data['company_name'], 'String');
      }
      if (data.hasOwnProperty('job_title')) {
        obj['job_title'] = ApiClient.convertToType(data['job_title'], 'String');
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
   * @member {module:model/PermissionProfileResponse} permission_profile
   */
  exports.prototype['permission_profile'] = undefined;
  /**
   * @member {Array.<module:model/MemberGroupResponse>} groups
   */
  exports.prototype['groups'] = undefined;
  /**
   * @member {String} company_name
   */
  exports.prototype['company_name'] = undefined;
  /**
   * @member {String} job_title
   */
  exports.prototype['job_title'] = undefined;



  return exports;
}));


