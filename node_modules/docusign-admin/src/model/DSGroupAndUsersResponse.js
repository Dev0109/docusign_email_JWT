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
    define(['ApiClient', 'model/DSGroupResponse', 'model/DSGroupUsersResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DSGroupResponse'), require('./DSGroupUsersResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.DSGroupAndUsersResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DSGroupResponse, root.DocusignAdmin.DSGroupUsersResponse);
  }
}(this, function(ApiClient, DSGroupResponse, DSGroupUsersResponse) {
  'use strict';


  /**
   * The DSGroupAndUsersResponse model module.
   * @module model/DSGroupAndUsersResponse
   */

  /**
   * Constructs a new <code>DSGroupAndUsersResponse</code>.
   * @alias module:model/DSGroupAndUsersResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DSGroupAndUsersResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DSGroupAndUsersResponse} obj Optional instance to populate.
   * @return {module:model/DSGroupAndUsersResponse} The populated <code>DSGroupAndUsersResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('group')) {
        obj['group'] = DSGroupResponse.constructFromObject(data['group']);
      }
      if (data.hasOwnProperty('group_users')) {
        obj['group_users'] = DSGroupUsersResponse.constructFromObject(data['group_users']);
      }
    }
    return obj;
  }

  /**
   * @member {module:model/DSGroupResponse} group
   */
  exports.prototype['group'] = undefined;
  /**
   * @member {module:model/DSGroupUsersResponse} group_users
   */
  exports.prototype['group_users'] = undefined;



  return exports;
}));


