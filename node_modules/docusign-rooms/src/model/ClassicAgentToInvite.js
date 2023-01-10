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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.ClassicAgentToInvite = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The ClassicAgentToInvite model module.
   * @module model/ClassicAgentToInvite
   */

  /**
   * Constructs a new <code>ClassicAgentToInvite</code>.
   * @alias module:model/ClassicAgentToInvite
   * @class
   * @param firstName {String} 
   * @param lastName {String} 
   * @param email {String} 
   * @param officeId {Number} 
   */
  var exports = function(firstName, lastName, email, officeId) {
    var _this = this;

    _this['firstName'] = firstName;    _this['lastName'] = lastName;    _this['email'] = email;    _this['officeId'] = officeId;
  };

  /**
   * Constructs a <code>ClassicAgentToInvite</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClassicAgentToInvite} obj Optional instance to populate.
   * @return {module:model/ClassicAgentToInvite} The populated <code>ClassicAgentToInvite</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('firstName')) {
        obj['firstName'] = ApiClient.convertToType(data['firstName'], 'String');
      }
      if (data.hasOwnProperty('lastName')) {
        obj['lastName'] = ApiClient.convertToType(data['lastName'], 'String');
      }
      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('officeId')) {
        obj['officeId'] = ApiClient.convertToType(data['officeId'], 'Number');
      }
      if (data.hasOwnProperty('companyTypeId')) {
        obj['companyTypeId'] = ApiClient.convertToType(data['companyTypeId'], 'String');
      }
      if (data.hasOwnProperty('eSignPermissionProfileId')) {
        obj['eSignPermissionProfileId'] = ApiClient.convertToType(data['eSignPermissionProfileId'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} firstName
   */
  exports.prototype['firstName'] = undefined;
  /**
   * @member {String} lastName
   */
  exports.prototype['lastName'] = undefined;
  /**
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * @member {Number} officeId
   */
  exports.prototype['officeId'] = undefined;
  /**
   * @member {String} companyTypeId
   */
  exports.prototype['companyTypeId'] = undefined;
  /**
   * Required when the company is tightly bound to an eSign account; otherwise ignored.
   * @member {String} eSignPermissionProfileId
   */
  exports.prototype['eSignPermissionProfileId'] = undefined;



  return exports;
}));


