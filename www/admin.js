import { auth, db, fn } from "./firebase-config.js";
import {
  signInWithEmailAndPassword,
  onAuthStateChanged,
  signOut,
  getIdTokenResult
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js";
import {
  ref,
  onValue
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-database.js";
import {
  httpsCallable
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-functions.js";

const $ = s => document.querySelector(s);

const state = {
  user: null,
  isAdmin: false,
  requestsUnsub: null,
  fraudUnsub: null
};

const approveWithdraw = httpsCallable(fn, "approveWithdraw");
const rejectWithdraw = httpsCallable(fn, "rejectWithdraw");

function setLoginState(text, info) {
  // স্ক্রিনশটের UI এর সাথে ম্যাচিং এলিমেন্ট (যদি আইডি না থাকে তবে টেক্সট কন্টেন্ট হ্যান্ডেল করবে)
  if ($("#loginState")) $("#loginState").textContent = text;
  if ($("#userInfo")) $("#userInfo").textContent = info || "";
}

function setLiveState(on) {
  if ($("#liveState")) $("#liveState").textContent = `Live: ${on ? "on" : "off"}`;
}

function tsToText(v) {
  if (!v) return "-";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
}

function renderRequests(list) {
  const container = $("#requestsBox") || $(".Withdraw-Requests-container") || document.body; 
  // যদি requestsBox আইডি না পান, তবে HTML ফাইলে কার্ডের ভেতরে id="requestsBox" লিখে দেবেন।
  
  if (!list.length) {
    container.innerHTML = '<div class="muted" style="padding:10px; color:#aaa;">No requests found</div>';
    return;
  }

  container.innerHTML = `
    <table style="width:100%; border-collapse: collapse; margin-top:10px; text-align:left;">
      <thead>
        <tr style="border-bottom: 1px solid #333; color: #888;">
          <th style="padding:8px;">User</th>
          <th style="padding:8px;">Method</th>
          <th style="padding:8px;">Number</th>
          <th style="padding:8px;">Points</th>
          <th style="padding:8px;">Status</th>
          <th style="padding:8px;">Time</th>
          <th style="padding:8px;">Action</th>
        </tr>
      </thead>
      <tbody>
        ${list.map(item => `
          <tr style="border-bottom: 1px solid #222;">
            <td style="padding:8px;">
              <div><strong>${item.name || "User"}</strong></div>
              <div style="font-size:11px; color:#666;">${item.uid || "-"}</div>
            </td>
            <td style="padding:8px;">${item.method || "-"}</td>
            <td style="padding:8px;">${item.number || "-"}</td>
            <td style="padding:8px; color: #4caf50;">${item.points ?? "-"}</td>
            <td style="padding:8px;"><span class="tag" style="background:#333; padding:2px 6px; border-radius:4px;">${item.status || "-"}</span></td>
            <td style="padding:8px; font-size:11px; color:#888;">${item.createdAtText || "-"}</td>
            <td style="padding:8px;">
              ${item.status === "pending" || item.status === "Pending" ? `
                <div class="row" style="display:flex; gap:6px">
                  <button class="green" style="background:#2e7d32; color:white; border:none; padding:4px 8px; border-radius:4px; cursor:pointer;" onclick="window.adminApprove('${item.id}')">Approve</button>
                  <button class="red" style="background:#c62828; color:white; border:none; padding:4px 8px; border-radius:4px; cursor:pointer;" onclick="window.adminReject('${item.id}')">Reject</button>
                </div>
              ` : `<span style="font-size:12px; color:#666;">Processed</span>`}
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderFrauds(list) {
  const container = $("#fraudBox") || $(".Fraud-Logs-container") || document.body;

  if (!list.length) {
    container.innerHTML = '<div class="muted" style="padding:10px; color:#aaa;">No fraud logs found</div>';
    return;
  }

  container.innerHTML = `
    <table style="width:100%; border-collapse: collapse; margin-top:10px; text-align:left;">
      <thead>
        <tr style="border-bottom: 1px solid #333; color: #888;">
          <th style="padding:8px;">Type</th>
          <th style="padding:8px;">Request</th>
          <th style="padding:8px;">User</th>
          <th style="padding:8px;">Admin</th>
          <th style="padding:8px;">Time</th>
        </tr>
      </thead>
      <tbody>
        ${list.map(item => `
          <tr style="border-bottom: 1px solid #222;">
            <td style="padding:8px;"><span class="tag" style="background:#c62828; color:white; padding:2px 6px; border-radius:4px; font-size:11px;">${item.type || "SUSPICIOUS"}</span></td>
            <td style="padding:8px; font-size:11px; color:#888;">${item.requestId || "-"}</td>
            <td style="padding:8px; font-size:11px;">${item.uid || "-"}</td>
            <td style="padding:8px; font-size:11px;">${item.adminUid || "-"}</td>
            <td style="padding:8px; font-size:11px; color:#888;">${item.createdAtText || "-"}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function detachLive() {
  if (state.requestsUnsub) state.requestsUnsub();
  if (state.fraudUnsub) state.fraudUnsub();
  state.requestsUnsub = null;
  state.fraudUnsub = null;
  setLiveState(false);
}

async function loadAdminState() {
  if (!state.user) return;

  try {
    const token = await getIdTokenResult(state.user, true);
    state.isAdmin = token.claims.admin === true;

    if (!state.isAdmin) {
      setLoginState("Access denied", "This account is not an admin account");
      await signOut(auth);
      alert("Warning: আপনি admin নন। আপনাকে auto logout করা হচ্ছে।");
      location.reload();
      return;
    }

    setLoginState("Admin logged in", `${state.user.email || "-"} | UID: ${state.user.uid}`);
    listenRequests();
    listenFrauds();
  } catch (e) {
    setLoginState("Auth error", e.message || "Failed to verify admin token");
  }
}

function listenRequests() {
  if (state.requestsUnsub) state.requestsUnsub();

  // আপনার ফায়ারবেস ডেটাবেস স্ট্রাকচার অনুযায়ী পাথ 'withdrawRequests' এ পরিবর্তন করা হলো
  state.requestsUnsub = onValue(ref(db, "withdrawRequests"), snap => {
    const data = snap.val() || {};
    const list = Object.entries(data)
      .map(([id, item]) => ({
        id,
        ...item,
        createdAtText: tsToText(item.createdAt)
      }))
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    renderRequests(list);
    setLiveState(true);
  });
}

function listenFrauds() {
  if (state.fraudUnsub) state.fraudUnsub();

  // পাথ 'fraudLogs' এ পরিবর্তন করা হলো
  state.fraudUnsub = onValue(ref(db, "fraudLogs"), snap => {
    const data = snap.val() || {};
    const list = Object.entries(data)
      .map(([id, item]) => ({
        id,
        ...item,
        createdAtText: tsToText(item.createdAt)
      }))
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    renderFrauds(list);
  });
}

async function adminLogin() {
  try {
    const email = $("#email").value.trim();
    const password = $("#password").value.trim();
    if (!email || !password) return alert("Email/password দিন");
    await signInWithEmailAndPassword(auth, email, password);
  } catch (e) {
    alert(e.message || "Admin login failed");
  }
}

async function adminLogout() {
  try {
    await signOut(auth);
    location.reload();
  } catch (e) {
    alert(e.message || "Logout failed");
  }
}

async function doApprove(requestId) {
  try {
    const res = await approveWithdraw({ requestId });
    alert("Approved successfully!");
  } catch (e) {
    alert(e.message || "Approve failed");
  }
}

async function doReject(requestId) {
  try {
    const res = await rejectWithdraw({ requestId });
    alert("Rejected successfully!");
  } catch (e) {
    alert(e.message || "Reject failed");
  }
}

window.adminLogin = adminLogin;
window.adminLogout = adminLogout;
window.adminApprove = doApprove;
window.adminReject = doReject;

onAuthStateChanged(auth, async user => {
  if (!user) {
    state.user = null;
    state.isAdmin = false;
    detachLive();
    setLoginState("Not logged in", "Waiting for admin authentication");
    return;
  }

  state.user = user;
  await loadAdminState();
});