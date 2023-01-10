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
    root.DocusignAdmin.AddDSGroupUsersResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DSGroupUserResponse);
  }
}(this, function(ApiClient, DSGroupUserResponse) {
  'use strict';


  /**
   * The AddDSGroupUsersResponse model module.
   * @module model/AddDSGroupUsersResponse
   */

  /**
   * Constructs a new <code>AddDSGroupUsersResponse</code>.
   * @alias module:model/AddDSGroupUsersResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>AddDSGroupUsersResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/AddDSGroupUsersResponse} obj Optional instance to populate.
   * @return {module:model/AddDSGroupUsersResponse} The populated <code>AddDSGroupUsersResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('is_success')) {
        obj['is_success'] = ApiClient.convertToType(data['is_success'], 'Boolean');
      }
      if (data.hasOwnProperty('TotalCount')) {
        obj['TotalCount'] = ApiClient.convertToType(data['TotalCount'], 'Number');
      }
      if (data.hasOwnProperty('users')) {
        obj['users'] = ApiClient.convertToType(data['users'], [DSGroupUserResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Boolean} is_success
   */
  exports.prototype['is_success'] = undefined;
  /**
   * @member {Number} TotalCount
   */
  exports.prototype['TotalCount'] = undefined;
  /**
   * @member {Array.<module:model/DSGroupUserResponse>} users
   */
  exports.prototype['users'] = undefined;



  return exports;
}));


