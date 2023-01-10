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
    define(['ApiClient', 'model/OrganizationExportAccount', 'model/OrganizationExportDomain'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrganizationExportAccount'), require('./OrganizationExportDomain'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationExportRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationExportAccount, root.DocusignAdmin.OrganizationExportDomain);
  }
}(this, function(ApiClient, OrganizationExportAccount, OrganizationExportDomain) {
  'use strict';


  /**
   * The OrganizationExportRequest model module.
   * @module model/OrganizationExportRequest
   */

  /**
   * Constructs a new <code>OrganizationExportRequest</code>.
   * @alias module:model/OrganizationExportRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationExportRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationExportRequest} obj Optional instance to populate.
   * @return {module:model/OrganizationExportRequest} The populated <code>OrganizationExportRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('type')) {
        obj['type'] = ApiClient.convertToType(data['type'], 'String');
      }
      if (data.hasOwnProperty('accounts')) {
        obj['accounts'] = ApiClient.convertToType(data['accounts'], [OrganizationExportAccount]);
      }
      if (data.hasOwnProperty('domains')) {
        obj['domains'] = ApiClient.convertToType(data['domains'], [OrganizationExportDomain]);
      }
    }
    return obj;
  }

  /**
   * @member {String} type
   */
  exports.prototype['type'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationExportAccount>} accounts
   */
  exports.prototype['accounts'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationExportDomain>} domains
   */
  exports.prototype['domains'] = undefined;



  return exports;
}));


