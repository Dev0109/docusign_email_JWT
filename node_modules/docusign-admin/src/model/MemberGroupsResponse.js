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
    define(['ApiClient', 'model/MemberGroupResponse', 'model/PagingResponseProperties'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./MemberGroupResponse'), require('./PagingResponseProperties'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.MemberGroupsResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.MemberGroupResponse, root.DocusignAdmin.PagingResponseProperties);
  }
}(this, function(ApiClient, MemberGroupResponse, PagingResponseProperties) {
  'use strict';


  /**
   * The MemberGroupsResponse model module.
   * @module model/MemberGroupsResponse
   */

  /**
   * Constructs a new <code>MemberGroupsResponse</code>.
   * @alias module:model/MemberGroupsResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>MemberGroupsResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/MemberGroupsResponse} obj Optional instance to populate.
   * @return {module:model/MemberGroupsResponse} The populated <code>MemberGroupsResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('groups')) {
        obj['groups'] = ApiClient.convertToType(data['groups'], [MemberGroupResponse]);
      }
      if (data.hasOwnProperty('paging')) {
        obj['paging'] = PagingResponseProperties.constructFromObject(data['paging']);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/MemberGroupResponse>} groups
   */
  exports.prototype['groups'] = undefined;
  /**
   * @member {module:model/PagingResponseProperties} paging
   */
  exports.prototype['paging'] = undefined;



  return exports;
}));


