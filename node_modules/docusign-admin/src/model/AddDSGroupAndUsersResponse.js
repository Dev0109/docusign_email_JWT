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
    define(['ApiClient', 'model/AddDSGroupUsersResponse', 'model/DSGroupResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./AddDSGroupUsersResponse'), require('./DSGroupResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.AddDSGroupAndUsersResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.AddDSGroupUsersResponse, root.DocusignAdmin.DSGroupResponse);
  }
}(this, function(ApiClient, AddDSGroupUsersResponse, DSGroupResponse) {
  'use strict';


  /**
   * The AddDSGroupAndUsersResponse model module.
   * @module model/AddDSGroupAndUsersResponse
   */

  /**
   * Constructs a new <code>AddDSGroupAndUsersResponse</code>.
   * @alias module:model/AddDSGroupAndUsersResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>AddDSGroupAndUsersResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/AddDSGroupAndUsersResponse} obj Optional instance to populate.
   * @return {module:model/AddDSGroupAndUsersResponse} The populated <code>AddDSGroupAndUsersResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('group')) {
        obj['group'] = DSGroupResponse.constructFromObject(data['group']);
      }
      if (data.hasOwnProperty('group_users')) {
        obj['group_users'] = AddDSGroupUsersResponse.constructFromObject(data['group_users']);
      }
    }
    return obj;
  }

  /**
   * @member {module:model/DSGroupResponse} group
   */
  exports.prototype['group'] = undefined;
  /**
   * @member {module:model/AddDSGroupUsersResponse} group_users
   */
  exports.prototype['group_users'] = undefined;



  return exports;
}));


