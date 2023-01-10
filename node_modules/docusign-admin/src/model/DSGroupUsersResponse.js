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
    root.DocusignAdmin.DSGroupUsersResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DSGroupUserResponse);
  }
}(this, function(ApiClient, DSGroupUserResponse) {
  'use strict';


  /**
   * The DSGroupUsersResponse model module.
   * @module model/DSGroupUsersResponse
   */

  /**
   * Constructs a new <code>DSGroupUsersResponse</code>.
   * @alias module:model/DSGroupUsersResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DSGroupUsersResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DSGroupUsersResponse} obj Optional instance to populate.
   * @return {module:model/DSGroupUsersResponse} The populated <code>DSGroupUsersResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('page')) {
        obj['page'] = ApiClient.convertToType(data['page'], 'Number');
      }
      if (data.hasOwnProperty('page_size')) {
        obj['page_size'] = ApiClient.convertToType(data['page_size'], 'Number');
      }
      if (data.hasOwnProperty('total_count')) {
        obj['total_count'] = ApiClient.convertToType(data['total_count'], 'Number');
      }
      if (data.hasOwnProperty('users')) {
        obj['users'] = ApiClient.convertToType(data['users'], [DSGroupUserResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Number} page
   */
  exports.prototype['page'] = undefined;
  /**
   * @member {Number} page_size
   */
  exports.prototype['page_size'] = undefined;
  /**
   * @member {Number} total_count
   */
  exports.prototype['total_count'] = undefined;
  /**
   * @member {Array.<module:model/DSGroupUserResponse>} users
   */
  exports.prototype['users'] = undefined;



  return exports;
}));


