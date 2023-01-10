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
    define(['ApiClient', 'model/UserDrilldownResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./UserDrilldownResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UsersDrilldownResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.UserDrilldownResponse);
  }
}(this, function(ApiClient, UserDrilldownResponse) {
  'use strict';


  /**
   * The UsersDrilldownResponse model module.
   * @module model/UsersDrilldownResponse
   */

  /**
   * Constructs a new <code>UsersDrilldownResponse</code>.
   * @alias module:model/UsersDrilldownResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>UsersDrilldownResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UsersDrilldownResponse} obj Optional instance to populate.
   * @return {module:model/UsersDrilldownResponse} The populated <code>UsersDrilldownResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('users')) {
        obj['users'] = ApiClient.convertToType(data['users'], [UserDrilldownResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/UserDrilldownResponse>} users
   */
  exports.prototype['users'] = undefined;



  return exports;
}));


