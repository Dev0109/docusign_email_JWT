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
    define(['ApiClient', 'model/AccessLevel', 'model/ClassicManagerPermissions'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./AccessLevel'), require('./ClassicManagerPermissions'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.ClassicManagerToInvite = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.AccessLevel, root.DocusignRooms.ClassicManagerPermissions);
  }
}(this, function(ApiClient, AccessLevel, ClassicManagerPermissions) {
  'use strict';


  /**
   * The ClassicManagerToInvite model module.
   * @module model/ClassicManagerToInvite
   */

  /**
   * Constructs a new <code>ClassicManagerToInvite</code>.
   * @alias module:model/ClassicManagerToInvite
   * @class
   * @param firstName {String} 
   * @param lastName {String} 
   * @param email {String} 
   * @param defaultOfficeId {Number} 
   * @param titleId {Number} 
   * @param accessLevel {module:model/AccessLevel} 
   * @param permissions {module:model/ClassicManagerPermissions} 
   */
  var exports = function(firstName, lastName, email, defaultOfficeId, titleId, accessLevel, permissions) {
    var _this = this;

    _this['firstName'] = firstName;    _this['lastName'] = lastName;    _this['email'] = email;    _this['defaultOfficeId'] = defaultOfficeId;    _this['titleId'] = titleId;    _this['accessLevel'] = accessLevel;    _this['permissions'] = permissions;
  };

  /**
   * Constructs a <code>ClassicManagerToInvite</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClassicManagerToInvite} obj Optional instance to populate.
   * @return {module:model/ClassicManagerToInvite} The populated <code>ClassicManagerToInvite</code> instance.
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
      if (data.hasOwnProperty('defaultOfficeId')) {
        obj['defaultOfficeId'] = ApiClient.convertToType(data['defaultOfficeId'], 'Number');
      }
      if (data.hasOwnProperty('titleId')) {
        obj['titleId'] = ApiClient.convertToType(data['titleId'], 'Number');
      }
      if (data.hasOwnProperty('accessLevel')) {
        obj['accessLevel'] = AccessLevel.constructFromObject(data['accessLevel']);
      }
      if (data.hasOwnProperty('permissions')) {
        obj['permissions'] = ClassicManagerPermissions.constructFromObject(data['permissions']);
      }
      if (data.hasOwnProperty('offices')) {
        obj['offices'] = ApiClient.convertToType(data['offices'], ['Number']);
      }
      if (data.hasOwnProperty('regions')) {
        obj['regions'] = ApiClient.convertToType(data['regions'], ['Number']);
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
   * @member {Number} defaultOfficeId
   */
  exports.prototype['defaultOfficeId'] = undefined;
  /**
   * @member {Number} titleId
   */
  exports.prototype['titleId'] = undefined;
  /**
   * @member {module:model/AccessLevel} accessLevel
   */
  exports.prototype['accessLevel'] = undefined;
  /**
   * @member {module:model/ClassicManagerPermissions} permissions
   */
  exports.prototype['permissions'] = undefined;
  /**
   * @member {Array.<Number>} offices
   */
  exports.prototype['offices'] = undefined;
  /**
   * @member {Array.<Number>} regions
   */
  exports.prototype['regions'] = undefined;
  /**
   * Required when the company is tightly bound to an eSign account; otherwise ignored.
   * @member {String} eSignPermissionProfileId
   */
  exports.prototype['eSignPermissionProfileId'] = undefined;



  return exports;
}));


