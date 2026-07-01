const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.database();

function assertAuth(context) {
  if (!context.auth || !context.auth.uid) {
    throw new functions.https.HttpsError("unauthenticated", "Login required");
  }
}

function assertSuperAdmin(context) {
  assertAuth(context);
  if (context.auth.token.superadmin !== true) {
    throw new functions.https.HttpsError("permission-denied", "Super admin only");
  }
}

function assertAdmin(context) {
  assertAuth(context);
  if (context.auth.token.admin !== true && context.auth.token.superadmin !== true) {
    throw new functions.https.HttpsError("permission-denied", "Admin only");
  }
}

async function mergeCustomClaims(uid, extraClaims) {
  const user = await admin.auth().getUser(uid);
  const oldClaims = user.customClaims || {};
  const nextClaims = { ...oldClaims, ...extraClaims };
  await admin.auth().setCustomUserClaims(uid, nextClaims);
  return nextClaims;
}

async function writeAuditLog(type, requestId, req, actorUid) {
  await db.ref("auditLogs").push({
    type,
    requestId: requestId || null,
    uid: req?.uid || null,
    actorUid: actorUid || null,
    amount: req?.amount ?? null,
    method: req?.method || null,
    createdAt: admin.database.ServerValue.TIMESTAMP
  });
}

async function updateWithdrawStatus(requestId, status, context) {
  const snap = await db.ref(`requests/${requestId}`).once("value");
  if (!snap.exists()) {
    throw new functions.https.HttpsError("not-found", "Request not found");
  }

  const req = snap.val() || {};
  const updates = {
    [`requests/${requestId}/status`]: status,
    [`requests/${requestId}/updatedAt`]: admin.database.ServerValue.TIMESTAMP
  };

  if (req.uid) {
    updates[`users/${req.uid}/withdrawStatus`] = status;
    updates[`users/${req.uid}/withdrawUpdatedAt`] = admin.database.ServerValue.TIMESTAMP;
  }

  await db.ref().update(updates);
  await writeAuditLog(status === "approved" ? "withdraw_approved" : "withdraw_rejected", requestId, req, context.auth.uid);
  return { success: true, requestId, status };
}

exports.bootstrapSuperAdmin = functions.https.onCall(async (data, context) => {
  try {
    assertAuth(context);

    const code = data && data.code;
    const targetUid = data && data.uid;

    if (code !== "BOOTSTRAP_2026_SUPERADMIN") {
      throw new functions.https.HttpsError("permission-denied", "Invalid bootstrap code");
    }

    if (!targetUid || typeof targetUid !== "string") {
      throw new functions.https.HttpsError("invalid-argument", "uid required");
    }

    const targetUser = await admin.auth().getUser(targetUid);
    const claims = await mergeCustomClaims(targetUid, {
      ...(targetUser.customClaims || {}),
      superadmin: true,
      admin: true
    });

    return { success: true, uid: targetUid, claims };
  } catch (error) {
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError("internal", error.message || "Bootstrap failed");
  }
});

exports.setAdminClaim = functions.https.onCall(async (data, context) => {
  try {
    assertSuperAdmin(context);

    const uid = data && data.uid;
    if (!uid || typeof uid !== "string") {
      throw new functions.https.HttpsError("invalid-argument", "uid required");
    }

    const claims = await mergeCustomClaims(uid, { admin: true });
    return { success: true, uid, claims };
  } catch (error) {
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError("internal", error.message || "Failed to set admin claim");
  }
});

exports.removeAdminClaim = functions.https.onCall(async (data, context) => {
  try {
    assertSuperAdmin(context);

    const uid = data && data.uid;
    if (!uid || typeof uid !== "string") {
      throw new functions.https.HttpsError("invalid-argument", "uid required");
    }

    const user = await admin.auth().getUser(uid);
    const oldClaims = user.customClaims || {};
    const { admin: _admin, ...rest } = oldClaims;
    await admin.auth().setCustomUserClaims(uid, rest);

    return { success: true, uid, claims: rest };
  } catch (error) {
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError("internal", error.message || "Failed to remove admin claim");
  }
});

exports.approveWithdraw = functions.https.onCall(async (data, context) => {
  try {
    assertAdmin(context);

    const requestId = data && data.requestId;
    if (!requestId || typeof requestId !== "string") {
      throw new functions.https.HttpsError("invalid-argument", "requestId required");
    }

    return await updateWithdrawStatus(requestId, "approved", context);
  } catch (error) {
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError("internal", error.message || "Approve failed");
  }
});

exports.rejectWithdraw = functions.https.onCall(async (data, context) => {
  try {
    assertAdmin(context);

    const requestId = data && data.requestId;
    if (!requestId || typeof requestId !== "string") {
      throw new functions.https.HttpsError("invalid-argument", "requestId required");
    }

    return await updateWithdrawStatus(requestId, "rejected", context);
  } catch (error) {
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError("internal", error.message || "Reject failed");
  }
});

exports.creditReferralBonus = functions.https.onCall(async (data, context) => {
  try {
    assertAuth(context);

    const ownerUid = data && data.ownerUid;
    if (!ownerUid || typeof ownerUid !== "string") {
      throw new functions.https.HttpsError("invalid-argument", "ownerUid required");
    }

    if (ownerUid === context.auth.uid) {
      throw new functions.https.HttpsError("failed-precondition", "Self referral not allowed");
    }

    const ownerSnap = await db.ref(`users/${ownerUid}`).once("value");
    if (!ownerSnap.exists()) {
      throw new functions.https.HttpsError("not-found", "Owner not found");
    }

    const owner = ownerSnap.val() || {};
    const newPoints = (owner.points || 0) + 100;
    const newCount = (owner.successfulReferrals || 0) + 1;

    await db.ref().update({
      [`users/${ownerUid}/points`]: newPoints,
      [`users/${ownerUid}/successfulReferrals`]: newCount
    });

    await writeAuditLog("referral_bonus", null, { uid: ownerUid, amount: 100, method: "referral" }, context.auth.uid);

    return { success: true, ownerUid, bonus: 100, points: newPoints, successfulReferrals: newCount };
  } catch (error) {
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError("internal", error.message || "Referral bonus failed");
  }
});