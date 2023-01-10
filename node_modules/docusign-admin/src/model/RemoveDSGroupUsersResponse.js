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
    define(['ApiClient', 'model/DSGroupUserResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DSGroupUserResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.RemoveDSGroupUsersResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DSGroupUserResponse);
  }
}(this, function(ApiClient, DSGroupUserResponse) {
  'use strict';


  /**
   * The RemoveDSGroupUsersResponse model module.
   * @module model/RemoveDSGroupUsersResponse
   */

  /**
   * Constructs a new <code>RemoveDSGroupUsersResponse</code>.
   * @alias module:model/RemoveDSGroupUsersResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>RemoveDSGroupUsersResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RemoveDSGroupUsersResponse} obj Optional instance to populate.
   * @return {module:model/RemoveDSGroupUsersResponse} The populated <code>RemoveDSGroupUsersResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('is_success')) {
        obj['is_success'] = ApiClient.convertToType(data['is_success'], 'Boolean');
      }
      if (data.hasOwnProperty('failed_users')) {
        obj['failed_users'] = ApiClient.convertToType(data['failed_users'], [DSGroupUserResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Boolean} is_success
   */
  exports.prototype['is_success'] = undefined;
  /**
   * @member {Array.<module:model/DSGroupUserResponse>} failed_users
   */
  exports.prototype['failed_users'] = undefined;



  return exports;
}));


