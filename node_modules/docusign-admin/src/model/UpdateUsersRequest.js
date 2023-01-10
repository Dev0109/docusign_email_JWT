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
    define(['ApiClient', 'model/UpdateUserRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./UpdateUserRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UpdateUsersRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.UpdateUserRequest);
  }
}(this, function(ApiClient, UpdateUserRequest) {
  'use strict';


  /**
   * The UpdateUsersRequest model module.
   * @module model/UpdateUsersRequest
   */

  /**
   * Constructs a new <code>UpdateUsersRequest</code>.
   * @alias module:model/UpdateUsersRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>UpdateUsersRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UpdateUsersRequest} obj Optional instance to populate.
   * @return {module:model/UpdateUsersRequest} The populated <code>UpdateUsersRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('users')) {
        obj['users'] = ApiClient.convertToType(data['users'], [UpdateUserRequest]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/UpdateUserRequest>} users
   */
  exports.prototype['users'] = undefined;



  return exports;
}));


