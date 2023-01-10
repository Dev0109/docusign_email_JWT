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
    define(['ApiClient', 'model/UpdateUserEmailRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./UpdateUserEmailRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UpdateUsersEmailRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.UpdateUserEmailRequest);
  }
}(this, function(ApiClient, UpdateUserEmailRequest) {
  'use strict';


  /**
   * The UpdateUsersEmailRequest model module.
   * @module model/UpdateUsersEmailRequest
   */

  /**
   * Constructs a new <code>UpdateUsersEmailRequest</code>.
   * @alias module:model/UpdateUsersEmailRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>UpdateUsersEmailRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UpdateUsersEmailRequest} obj Optional instance to populate.
   * @return {module:model/UpdateUsersEmailRequest} The populated <code>UpdateUsersEmailRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('users')) {
        obj['users'] = ApiClient.convertToType(data['users'], [UpdateUserEmailRequest]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/UpdateUserEmailRequest>} users
   */
  exports.prototype['users'] = undefined;



  return exports;
}));


