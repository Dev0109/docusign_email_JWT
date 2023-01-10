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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.DSGroupUsersAddRequest = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The DSGroupUsersAddRequest model module.
   * @module model/DSGroupUsersAddRequest
   */

  /**
   * Constructs a new <code>DSGroupUsersAddRequest</code>.
   * @alias module:model/DSGroupUsersAddRequest
   * @class
   * @param userIds {Array.<String>} 
   */
  var exports = function(userIds) {
    var _this = this;

    _this['user_ids'] = userIds;
  };

  /**
   * Constructs a <code>DSGroupUsersAddRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DSGroupUsersAddRequest} obj Optional instance to populate.
   * @return {module:model/DSGroupUsersAddRequest} The populated <code>DSGroupUsersAddRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('user_ids')) {
        obj['user_ids'] = ApiClient.convertToType(data['user_ids'], ['String']);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<String>} user_ids
   */
  exports.prototype['user_ids'] = undefined;



  return exports;
}));


