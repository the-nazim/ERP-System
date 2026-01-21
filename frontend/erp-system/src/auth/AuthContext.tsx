import React, {createContext, useEffect, useState} from "react";
import api from "../api/axios";
import type { User, AuthResponse } from "../types/auth";

interface AuthContextType {
    user: User | null;
    login: (email: string, password: string) => Promise<void>;
    signup: (name: string, email: string, password: string) => Promise<void>;
    logout: () => void;
    loading: boolean;
}

export const AuthContext = createContext<AuthContextType | null>(null);

