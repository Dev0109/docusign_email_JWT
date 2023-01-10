/**
 * DocuSign Rooms API - v2
 * An API for an integrator to access the features of DocuSign Rooms
 *
 * OpenAPI spec version: v2
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/ProductVersion'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ProductVersion'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.AccountSummary = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.ProductVersion);
  }
}(this, function(ApiClient, ProductVersion) {
  'use strict';


  /**
   * The AccountSummary model module.
   * @module model/AccountSummary
   */

  /**
   * Constructs a new <code>AccountSummary</code>.
   * @alias module:model/AccountSummary
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>AccountSummary</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/AccountSummary} obj Optional instance to populate.
   * @return {module:model/AccountSummary} The populated <code>AccountSummary</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('companyId')) {
        obj['companyId'] = ApiClient.convertToType(data['companyId'], 'Number');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('companyVersion')) {
        obj['companyVersion'] = ProductVersion.constructFromObject(data['companyVersion']);
      }
      if (data.hasOwnProperty('docuSignAccountGuid')) {
        obj['docuSignAccountGuid'] = ApiClient.convertToType(data['docuSignAccountGuid'], 'String');
      }
      if (data.hasOwnProperty('defaultFieldSetId')) {
        obj['defaultFieldSetId'] = ApiClient.convertToType(data['defaultFieldSetId'], 'String');
      }
      if (data.hasOwnProperty('requireOfficeLibraryAssignments')) {
        obj['requireOfficeLibraryAssignments'] = ApiClient.convertToType(data['requireOfficeLibraryAssignments'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {Number} companyId
   */
  exports.prototype['companyId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {module:model/ProductVersion} companyVersion
   */
  exports.prototype['companyVersion'] = undefined;
  /**
   * @member {String} docuSignAccountGuid
   */
  exports.prototype['docuSignAccountGuid'] = undefined;
  /**
   * @member {String} defaultFieldSetId
   */
  exports.prototype['defaultFieldSetId'] = undefined;
  /**
   * @member {Boolean} requireOfficeLibraryAssignments
   */
  exports.prototype['requireOfficeLibraryAssignments'] = undefined;



  return exports;
}));


