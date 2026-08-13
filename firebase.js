// Firebase project config for alaga-production.
// This key is safe to be public — it identifies the project, it does not
// grant privileged access. Actual access control happens via Firebase Auth
// rules and (once built) the backend's own authorization checks.
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

const firebaseConfig = {
  apiKey: "AIzaSyAKwF8yXZd3Bwy9oC-FOjX_uECmNbtt0no",
  authDomain: "alaga-production.firebaseapp.com",
  projectId: "alaga-production",
  storageBucket: "alaga-production.firebasestorage.app",
  messagingSenderId: "1017852082045",
  appId: "1:1017852082045:web:27560933d61c0c4079be14",
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
