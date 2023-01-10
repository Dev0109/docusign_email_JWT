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
    define(['ApiClient', 'model/OriginOfLead'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OriginOfLead'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalOriginsOfLeads = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.OriginOfLead);
  }
}(this, function(ApiClient, OriginOfLead) {
  'use strict';


  /**
   * The GlobalOriginsOfLeads model module.
   * @module model/GlobalOriginsOfLeads
   */

  /**
   * Constructs a new <code>GlobalOriginsOfLeads</code>.
   * @alias module:model/GlobalOriginsOfLeads
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalOriginsOfLeads</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalOriginsOfLeads} obj Optional instance to populate.
   * @return {module:model/GlobalOriginsOfLeads} The populated <code>GlobalOriginsOfLeads</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('originsOfLeads')) {
        obj['originsOfLeads'] = ApiClient.convertToType(data['originsOfLeads'], [OriginOfLead]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/OriginOfLead>} originsOfLeads
   */
  exports.prototype['originsOfLeads'] = undefined;



  return exports;
}));


