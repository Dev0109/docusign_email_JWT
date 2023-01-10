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
    root.DocusignRooms.ClassicManagerPermissions = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The ClassicManagerPermissions model module.
   * @module model/ClassicManagerPermissions
   */

  /**
   * Constructs a new <code>ClassicManagerPermissions</code>.
   * @alias module:model/ClassicManagerPermissions
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ClassicManagerPermissions</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClassicManagerPermissions} obj Optional instance to populate.
   * @return {module:model/ClassicManagerPermissions} The populated <code>ClassicManagerPermissions</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('isVisibleInTransactionRooms')) {
        obj['isVisibleInTransactionRooms'] = ApiClient.convertToType(data['isVisibleInTransactionRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canDeleteCompanyRooms')) {
        obj['canDeleteCompanyRooms'] = ApiClient.convertToType(data['canDeleteCompanyRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canDeleteCompanyDocuments')) {
        obj['canDeleteCompanyDocuments'] = ApiClient.convertToType(data['canDeleteCompanyDocuments'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageCompanyRooms')) {
        obj['canManageCompanyRooms'] = ApiClient.convertToType(data['canManageCompanyRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageCompanyAccount')) {
        obj['canManageCompanyAccount'] = ApiClient.convertToType(data['canManageCompanyAccount'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageCompanySharedLibrary')) {
        obj['canManageCompanySharedLibrary'] = ApiClient.convertToType(data['canManageCompanySharedLibrary'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageCompanyMembers')) {
        obj['canManageCompanyMembers'] = ApiClient.convertToType(data['canManageCompanyMembers'], 'Boolean');
      }
      if (data.hasOwnProperty('canCloseCompanyRooms')) {
        obj['canCloseCompanyRooms'] = ApiClient.convertToType(data['canCloseCompanyRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canApproveCompanyChecklists')) {
        obj['canApproveCompanyChecklists'] = ApiClient.convertToType(data['canApproveCompanyChecklists'], 'Boolean');
      }
      if (data.hasOwnProperty('isCompanySystemAdmin')) {
        obj['isCompanySystemAdmin'] = ApiClient.convertToType(data['isCompanySystemAdmin'], 'Boolean');
      }
      if (data.hasOwnProperty('isRegionManager')) {
        obj['isRegionManager'] = ApiClient.convertToType(data['isRegionManager'], 'Boolean');
      }
      if (data.hasOwnProperty('isOfficeManager')) {
        obj['isOfficeManager'] = ApiClient.convertToType(data['isOfficeManager'], 'Boolean');
      }
      if (data.hasOwnProperty('autoAccessToCompanyRooms')) {
        obj['autoAccessToCompanyRooms'] = ApiClient.convertToType(data['autoAccessToCompanyRooms'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {Boolean} isVisibleInTransactionRooms
   */
  exports.prototype['isVisibleInTransactionRooms'] = undefined;
  /**
   * @member {Boolean} canDeleteCompanyRooms
   */
  exports.prototype['canDeleteCompanyRooms'] = undefined;
  /**
   * @member {Boolean} canDeleteCompanyDocuments
   */
  exports.prototype['canDeleteCompanyDocuments'] = undefined;
  /**
   * @member {Boolean} canManageCompanyRooms
   */
  exports.prototype['canManageCompanyRooms'] = undefined;
  /**
   * @member {Boolean} canManageCompanyAccount
   */
  exports.prototype['canManageCompanyAccount'] = undefined;
  /**
   * @member {Boolean} canManageCompanySharedLibrary
   */
  exports.prototype['canManageCompanySharedLibrary'] = undefined;
  /**
   * @member {Boolean} canManageCompanyMembers
   */
  exports.prototype['canManageCompanyMembers'] = undefined;
  /**
   * @member {Boolean} canCloseCompanyRooms
   */
  exports.prototype['canCloseCompanyRooms'] = undefined;
  /**
   * @member {Boolean} canApproveCompanyChecklists
   */
  exports.prototype['canApproveCompanyChecklists'] = undefined;
  /**
   * @member {Boolean} isCompanySystemAdmin
   */
  exports.prototype['isCompanySystemAdmin'] = undefined;
  /**
   * @member {Boolean} isRegionManager
   */
  exports.prototype['isRegionManager'] = undefined;
  /**
   * @member {Boolean} isOfficeManager
   */
  exports.prototype['isOfficeManager'] = undefined;
  /**
   * @member {Boolean} autoAccessToCompanyRooms
   */
  exports.prototype['autoAccessToCompanyRooms'] = undefined;



  return exports;
}));


