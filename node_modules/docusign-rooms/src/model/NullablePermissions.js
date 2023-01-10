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
    root.DocusignRooms.NullablePermissions = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The NullablePermissions model module.
   * @module model/NullablePermissions
   */

  /**
   * Constructs a new <code>NullablePermissions</code>.
   * @alias module:model/NullablePermissions
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>NullablePermissions</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/NullablePermissions} obj Optional instance to populate.
   * @return {module:model/NullablePermissions} The populated <code>NullablePermissions</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('canAddUsersToRooms')) {
        obj['canAddUsersToRooms'] = ApiClient.convertToType(data['canAddUsersToRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canCreateRooms')) {
        obj['canCreateRooms'] = ApiClient.convertToType(data['canCreateRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canSubmitRoomsForReview')) {
        obj['canSubmitRoomsForReview'] = ApiClient.convertToType(data['canSubmitRoomsForReview'], 'Boolean');
      }
      if (data.hasOwnProperty('canCloseRooms')) {
        obj['canCloseRooms'] = ApiClient.convertToType(data['canCloseRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canReopenRooms')) {
        obj['canReopenRooms'] = ApiClient.convertToType(data['canReopenRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canDeleteOwnedRooms')) {
        obj['canDeleteOwnedRooms'] = ApiClient.convertToType(data['canDeleteOwnedRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('autoAccessToRooms')) {
        obj['autoAccessToRooms'] = ApiClient.convertToType(data['autoAccessToRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canExportRoomActivityDetailsPeople')) {
        obj['canExportRoomActivityDetailsPeople'] = ApiClient.convertToType(data['canExportRoomActivityDetailsPeople'], 'Boolean');
      }
      if (data.hasOwnProperty('isVisibleInRooms')) {
        obj['isVisibleInRooms'] = ApiClient.convertToType(data['isVisibleInRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canCopyRoomDetails')) {
        obj['canCopyRoomDetails'] = ApiClient.convertToType(data['canCopyRoomDetails'], 'Boolean');
      }
      if (data.hasOwnProperty('canEditAnyRoomRole')) {
        obj['canEditAnyRoomRole'] = ApiClient.convertToType(data['canEditAnyRoomRole'], 'Boolean');
      }
      if (data.hasOwnProperty('canEditInvitedRoomRole')) {
        obj['canEditInvitedRoomRole'] = ApiClient.convertToType(data['canEditInvitedRoomRole'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageAnyUserRoomAccess')) {
        obj['canManageAnyUserRoomAccess'] = ApiClient.convertToType(data['canManageAnyUserRoomAccess'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageInvitedUserRoomAccess')) {
        obj['canManageInvitedUserRoomAccess'] = ApiClient.convertToType(data['canManageInvitedUserRoomAccess'], 'Boolean');
      }
      if (data.hasOwnProperty('canViewRoomDetails')) {
        obj['canViewRoomDetails'] = ApiClient.convertToType(data['canViewRoomDetails'], 'Boolean');
      }
      if (data.hasOwnProperty('canViewAndEditRoomDetails')) {
        obj['canViewAndEditRoomDetails'] = ApiClient.convertToType(data['canViewAndEditRoomDetails'], 'Boolean');
      }
      if (data.hasOwnProperty('canSendRoomDetailsToLoneWolf')) {
        obj['canSendRoomDetailsToLoneWolf'] = ApiClient.convertToType(data['canSendRoomDetailsToLoneWolf'], 'Boolean');
      }
      if (data.hasOwnProperty('canAddDocuments')) {
        obj['canAddDocuments'] = ApiClient.convertToType(data['canAddDocuments'], 'Boolean');
      }
      if (data.hasOwnProperty('canAddDocumentsFromFormGroups')) {
        obj['canAddDocumentsFromFormGroups'] = ApiClient.convertToType(data['canAddDocumentsFromFormGroups'], 'Boolean');
      }
      if (data.hasOwnProperty('canAddDocumentsFromFormLibraries')) {
        obj['canAddDocumentsFromFormLibraries'] = ApiClient.convertToType(data['canAddDocumentsFromFormLibraries'], 'Boolean');
      }
      if (data.hasOwnProperty('documentsViewableByOthersInRoomFromOffice')) {
        obj['documentsViewableByOthersInRoomFromOffice'] = ApiClient.convertToType(data['documentsViewableByOthersInRoomFromOffice'], 'Boolean');
      }
      if (data.hasOwnProperty('documentsAutoOwnedByPeers')) {
        obj['documentsAutoOwnedByPeers'] = ApiClient.convertToType(data['documentsAutoOwnedByPeers'], 'Boolean');
      }
      if (data.hasOwnProperty('canDeleteOwnedDocuments')) {
        obj['canDeleteOwnedDocuments'] = ApiClient.convertToType(data['canDeleteOwnedDocuments'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageSharedDocs')) {
        obj['canManageSharedDocs'] = ApiClient.convertToType(data['canManageSharedDocs'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageFormGroups')) {
        obj['canManageFormGroups'] = ApiClient.convertToType(data['canManageFormGroups'], 'Boolean');
      }
      if (data.hasOwnProperty('canShareDocsNotOwned')) {
        obj['canShareDocsNotOwned'] = ApiClient.convertToType(data['canShareDocsNotOwned'], 'Boolean');
      }
      if (data.hasOwnProperty('canAddTasksToAnyTaskLists')) {
        obj['canAddTasksToAnyTaskLists'] = ApiClient.convertToType(data['canAddTasksToAnyTaskLists'], 'Boolean');
      }
      if (data.hasOwnProperty('canEditEditableTasks')) {
        obj['canEditEditableTasks'] = ApiClient.convertToType(data['canEditEditableTasks'], 'Boolean');
      }
      if (data.hasOwnProperty('canEditAnyTasks')) {
        obj['canEditAnyTasks'] = ApiClient.convertToType(data['canEditAnyTasks'], 'Boolean');
      }
      if (data.hasOwnProperty('canDeleteDeletableTasks')) {
        obj['canDeleteDeletableTasks'] = ApiClient.convertToType(data['canDeleteDeletableTasks'], 'Boolean');
      }
      if (data.hasOwnProperty('canDeleteAnyTasks')) {
        obj['canDeleteAnyTasks'] = ApiClient.convertToType(data['canDeleteAnyTasks'], 'Boolean');
      }
      if (data.hasOwnProperty('canApplyTaskList')) {
        obj['canApplyTaskList'] = ApiClient.convertToType(data['canApplyTaskList'], 'Boolean');
      }
      if (data.hasOwnProperty('canRemoveAnyTaskList')) {
        obj['canRemoveAnyTaskList'] = ApiClient.convertToType(data['canRemoveAnyTaskList'], 'Boolean');
      }
      if (data.hasOwnProperty('canSubmitTaskList')) {
        obj['canSubmitTaskList'] = ApiClient.convertToType(data['canSubmitTaskList'], 'Boolean');
      }
      if (data.hasOwnProperty('canAutoSubmitTaskList')) {
        obj['canAutoSubmitTaskList'] = ApiClient.convertToType(data['canAutoSubmitTaskList'], 'Boolean');
      }
      if (data.hasOwnProperty('canReviewTaskList')) {
        obj['canReviewTaskList'] = ApiClient.convertToType(data['canReviewTaskList'], 'Boolean');
      }
      if (data.hasOwnProperty('canAutoApproveTaskList')) {
        obj['canAutoApproveTaskList'] = ApiClient.convertToType(data['canAutoApproveTaskList'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageTaskTemplatesForAllRegionsAllOffices')) {
        obj['canManageTaskTemplatesForAllRegionsAllOffices'] = ApiClient.convertToType(data['canManageTaskTemplatesForAllRegionsAllOffices'], 'Boolean');
      }
      if (data.hasOwnProperty('canApplyRoomTemplates')) {
        obj['canApplyRoomTemplates'] = ApiClient.convertToType(data['canApplyRoomTemplates'], 'Boolean');
      }
      if (data.hasOwnProperty('canAddTasksToRooms')) {
        obj['canAddTasksToRooms'] = ApiClient.convertToType(data['canAddTasksToRooms'], 'Boolean');
      }
      if (data.hasOwnProperty('canCreateAndManagePackages')) {
        obj['canCreateAndManagePackages'] = ApiClient.convertToType(data['canCreateAndManagePackages'], 'Boolean');
      }
      if (data.hasOwnProperty('canAddMemberAndSetRoleLowerAccessLevel')) {
        obj['canAddMemberAndSetRoleLowerAccessLevel'] = ApiClient.convertToType(data['canAddMemberAndSetRoleLowerAccessLevel'], 'Boolean');
      }
      if (data.hasOwnProperty('canAddMemberAndSetRoleSameAccessLevel')) {
        obj['canAddMemberAndSetRoleSameAccessLevel'] = ApiClient.convertToType(data['canAddMemberAndSetRoleSameAccessLevel'], 'Boolean');
      }
      if (data.hasOwnProperty('canChangeMemberRoleLowerAccessLevel')) {
        obj['canChangeMemberRoleLowerAccessLevel'] = ApiClient.convertToType(data['canChangeMemberRoleLowerAccessLevel'], 'Boolean');
      }
      if (data.hasOwnProperty('canChangeMemberRoleSameAccessLevel')) {
        obj['canChangeMemberRoleSameAccessLevel'] = ApiClient.convertToType(data['canChangeMemberRoleSameAccessLevel'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageMemberLowerAccessLevel')) {
        obj['canManageMemberLowerAccessLevel'] = ApiClient.convertToType(data['canManageMemberLowerAccessLevel'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageMemberSameAccessLevel')) {
        obj['canManageMemberSameAccessLevel'] = ApiClient.convertToType(data['canManageMemberSameAccessLevel'], 'Boolean');
      }
      if (data.hasOwnProperty('canRemoveCompanyMemberLowerAccessLevel')) {
        obj['canRemoveCompanyMemberLowerAccessLevel'] = ApiClient.convertToType(data['canRemoveCompanyMemberLowerAccessLevel'], 'Boolean');
      }
      if (data.hasOwnProperty('canRemoveCompanyMemberSameAccessLevel')) {
        obj['canRemoveCompanyMemberSameAccessLevel'] = ApiClient.convertToType(data['canRemoveCompanyMemberSameAccessLevel'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageAccount')) {
        obj['canManageAccount'] = ApiClient.convertToType(data['canManageAccount'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageLogo')) {
        obj['canManageLogo'] = ApiClient.convertToType(data['canManageLogo'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageRoomDetails')) {
        obj['canManageRoomDetails'] = ApiClient.convertToType(data['canManageRoomDetails'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageRoomTemplates')) {
        obj['canManageRoomTemplates'] = ApiClient.convertToType(data['canManageRoomTemplates'], 'Boolean');
      }
      if (data.hasOwnProperty('canManageIntegrationSettings')) {
        obj['canManageIntegrationSettings'] = ApiClient.convertToType(data['canManageIntegrationSettings'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {Boolean} canAddUsersToRooms
   */
  exports.prototype['canAddUsersToRooms'] = undefined;
  /**
   * @member {Boolean} canCreateRooms
   */
  exports.prototype['canCreateRooms'] = undefined;
  /**
   * @member {Boolean} canSubmitRoomsForReview
   */
  exports.prototype['canSubmitRoomsForReview'] = undefined;
  /**
   * @member {Boolean} canCloseRooms
   */
  exports.prototype['canCloseRooms'] = undefined;
  /**
   * @member {Boolean} canReopenRooms
   */
  exports.prototype['canReopenRooms'] = undefined;
  /**
   * @member {Boolean} canDeleteOwnedRooms
   */
  exports.prototype['canDeleteOwnedRooms'] = undefined;
  /**
   * @member {Boolean} autoAccessToRooms
   */
  exports.prototype['autoAccessToRooms'] = undefined;
  /**
   * @member {Boolean} canExportRoomActivityDetailsPeople
   */
  exports.prototype['canExportRoomActivityDetailsPeople'] = undefined;
  /**
   * @member {Boolean} isVisibleInRooms
   */
  exports.prototype['isVisibleInRooms'] = undefined;
  /**
   * @member {Boolean} canCopyRoomDetails
   */
  exports.prototype['canCopyRoomDetails'] = undefined;
  /**
   * @member {Boolean} canEditAnyRoomRole
   */
  exports.prototype['canEditAnyRoomRole'] = undefined;
  /**
   * @member {Boolean} canEditInvitedRoomRole
   */
  exports.prototype['canEditInvitedRoomRole'] = undefined;
  /**
   * @member {Boolean} canManageAnyUserRoomAccess
   */
  exports.prototype['canManageAnyUserRoomAccess'] = undefined;
  /**
   * @member {Boolean} canManageInvitedUserRoomAccess
   */
  exports.prototype['canManageInvitedUserRoomAccess'] = undefined;
  /**
   * @member {Boolean} canViewRoomDetails
   */
  exports.prototype['canViewRoomDetails'] = undefined;
  /**
   * @member {Boolean} canViewAndEditRoomDetails
   */
  exports.prototype['canViewAndEditRoomDetails'] = undefined;
  /**
   * @member {Boolean} canSendRoomDetailsToLoneWolf
   */
  exports.prototype['canSendRoomDetailsToLoneWolf'] = undefined;
  /**
   * @member {Boolean} canAddDocuments
   */
  exports.prototype['canAddDocuments'] = undefined;
  /**
   * @member {Boolean} canAddDocumentsFromFormGroups
   */
  exports.prototype['canAddDocumentsFromFormGroups'] = undefined;
  /**
   * @member {Boolean} canAddDocumentsFromFormLibraries
   */
  exports.prototype['canAddDocumentsFromFormLibraries'] = undefined;
  /**
   * @member {Boolean} documentsViewableByOthersInRoomFromOffice
   */
  exports.prototype['documentsViewableByOthersInRoomFromOffice'] = undefined;
  /**
   * @member {Boolean} documentsAutoOwnedByPeers
   */
  exports.prototype['documentsAutoOwnedByPeers'] = undefined;
  /**
   * @member {Boolean} canDeleteOwnedDocuments
   */
  exports.prototype['canDeleteOwnedDocuments'] = undefined;
  /**
   * @member {Boolean} canManageSharedDocs
   */
  exports.prototype['canManageSharedDocs'] = undefined;
  /**
   * @member {Boolean} canManageFormGroups
   */
  exports.prototype['canManageFormGroups'] = undefined;
  /**
   * @member {Boolean} canShareDocsNotOwned
   */
  exports.prototype['canShareDocsNotOwned'] = undefined;
  /**
   * @member {Boolean} canAddTasksToAnyTaskLists
   */
  exports.prototype['canAddTasksToAnyTaskLists'] = undefined;
  /**
   * @member {Boolean} canEditEditableTasks
   */
  exports.prototype['canEditEditableTasks'] = undefined;
  /**
   * @member {Boolean} canEditAnyTasks
   */
  exports.prototype['canEditAnyTasks'] = undefined;
  /**
   * @member {Boolean} canDeleteDeletableTasks
   */
  exports.prototype['canDeleteDeletableTasks'] = undefined;
  /**
   * @member {Boolean} canDeleteAnyTasks
   */
  exports.prototype['canDeleteAnyTasks'] = undefined;
  /**
   * @member {Boolean} canApplyTaskList
   */
  exports.prototype['canApplyTaskList'] = undefined;
  /**
   * @member {Boolean} canRemoveAnyTaskList
   */
  exports.prototype['canRemoveAnyTaskList'] = undefined;
  /**
   * @member {Boolean} canSubmitTaskList
   */
  exports.prototype['canSubmitTaskList'] = undefined;
  /**
   * @member {Boolean} canAutoSubmitTaskList
   */
  exports.prototype['canAutoSubmitTaskList'] = undefined;
  /**
   * @member {Boolean} canReviewTaskList
   */
  exports.prototype['canReviewTaskList'] = undefined;
  /**
   * @member {Boolean} canAutoApproveTaskList
   */
  exports.prototype['canAutoApproveTaskList'] = undefined;
  /**
   * @member {Boolean} canManageTaskTemplatesForAllRegionsAllOffices
   */
  exports.prototype['canManageTaskTemplatesForAllRegionsAllOffices'] = undefined;
  /**
   * @member {Boolean} canApplyRoomTemplates
   */
  exports.prototype['canApplyRoomTemplates'] = undefined;
  /**
   * @member {Boolean} canAddTasksToRooms
   */
  exports.prototype['canAddTasksToRooms'] = undefined;
  /**
   * @member {Boolean} canCreateAndManagePackages
   */
  exports.prototype['canCreateAndManagePackages'] = undefined;
  /**
   * @member {Boolean} canAddMemberAndSetRoleLowerAccessLevel
   */
  exports.prototype['canAddMemberAndSetRoleLowerAccessLevel'] = undefined;
  /**
   * @member {Boolean} canAddMemberAndSetRoleSameAccessLevel
   */
  exports.prototype['canAddMemberAndSetRoleSameAccessLevel'] = undefined;
  /**
   * @member {Boolean} canChangeMemberRoleLowerAccessLevel
   */
  exports.prototype['canChangeMemberRoleLowerAccessLevel'] = undefined;
  /**
   * @member {Boolean} canChangeMemberRoleSameAccessLevel
   */
  exports.prototype['canChangeMemberRoleSameAccessLevel'] = undefined;
  /**
   * @member {Boolean} canManageMemberLowerAccessLevel
   */
  exports.prototype['canManageMemberLowerAccessLevel'] = undefined;
  /**
   * @member {Boolean} canManageMemberSameAccessLevel
   */
  exports.prototype['canManageMemberSameAccessLevel'] = undefined;
  /**
   * @member {Boolean} canRemoveCompanyMemberLowerAccessLevel
   */
  exports.prototype['canRemoveCompanyMemberLowerAccessLevel'] = undefined;
  /**
   * @member {Boolean} canRemoveCompanyMemberSameAccessLevel
   */
  exports.prototype['canRemoveCompanyMemberSameAccessLevel'] = undefined;
  /**
   * @member {Boolean} canManageAccount
   */
  exports.prototype['canManageAccount'] = undefined;
  /**
   * @member {Boolean} canManageLogo
   */
  exports.prototype['canManageLogo'] = undefined;
  /**
   * @member {Boolean} canManageRoomDetails
   */
  exports.prototype['canManageRoomDetails'] = undefined;
  /**
   * @member {Boolean} canManageRoomTemplates
   */
  exports.prototype['canManageRoomTemplates'] = undefined;
  /**
   * @member {Boolean} canManageIntegrationSettings
   */
  exports.prototype['canManageIntegrationSettings'] = undefined;



  return exports;
}));


