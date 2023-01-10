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
    define(['ApiClient', 'model/GroupRequest', 'model/PermissionProfileRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./GroupRequest'), require('./PermissionProfileRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.NewUserRequestAccountProperties = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.GroupRequest, root.DocusignAdmin.PermissionProfileRequest);
  }
}(this, function(ApiClient, GroupRequest, PermissionProfileRequest) {
  'use strict';


  /**
   * The NewUserRequestAccountProperties model module.
   * @module model/NewUserRequestAccountProperties
   */

  /**
   * Constructs a new <code>NewUserRequestAccountProperties</code>.
   * @alias module:model/NewUserRequestAccountProperties
   * @class
   * @param id {String} 
   */
  var exports = function(id) {
    var _this = this;

    _this['id'] = id;
  };

  /**
   * Constructs a <code>NewUserRequestAccountProperties</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/NewUserRequestAccountProperties} obj Optional instance to populate.
   * @return {module:model/NewUserRequestAccountProperties} The populated <code>NewUserRequestAccountProperties</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('permission_profile')) {
        obj['permission_profile'] = PermissionProfileRequest.constructFromObject(data['permission_profile']);
      }
      if (data.hasOwnProperty('groups')) {
        obj['groups'] = ApiClient.convertToType(data['groups'], [GroupRequest]);
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
   * @member {module:model/PermissionProfileRequest} permission_profile
   */
  exports.prototype['permission_profile'] = undefined;
  /**
   * @member {Array.<module:model/GroupRequest>} groups
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


