export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.18"
  }
  public: {
    Tables: {
      ai_consents: {
        Row: {
          conversation_id: string
          granted_at: string
          id: string
          revoked_at: string | null
          user_id: string
        }
        Insert: {
          conversation_id: string
          granted_at?: string
          id?: string
          revoked_at?: string | null
          user_id: string
        }
        Update: {
          conversation_id?: string
          granted_at?: string
          id?: string
          revoked_at?: string | null
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "ai_consents_conversation_id_fkey"
            columns: ["conversation_id"]
            isOneToOne: false
            referencedRelation: "conversations"
            referencedColumns: ["id"]
          },
        ]
      }
      call_signals: {
        Row: {
          call_id: string
          created_at: string
          id: number
          kind: string
          payload: Json
          sender_id: string
        }
        Insert: {
          call_id: string
          created_at?: string
          id?: never
          kind: string
          payload: Json
          sender_id: string
        }
        Update: {
          call_id?: string
          created_at?: string
          id?: never
          kind?: string
          payload?: Json
          sender_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "call_signals_call_id_fkey"
            columns: ["call_id"]
            isOneToOne: false
            referencedRelation: "calls"
            referencedColumns: ["id"]
          },
        ]
      }
      calls: {
        Row: {
          conversation_id: string
          ended_at: string | null
          id: string
          initiator_id: string
          route: string | null
          started_at: string
          status: Database["public"]["Enums"]["call_status"]
        }
        Insert: {
          conversation_id: string
          ended_at?: string | null
          id?: string
          initiator_id: string
          route?: string | null
          started_at?: string
          status?: Database["public"]["Enums"]["call_status"]
        }
        Update: {
          conversation_id?: string
          ended_at?: string | null
          id?: string
          initiator_id?: string
          route?: string | null
          started_at?: string
          status?: Database["public"]["Enums"]["call_status"]
        }
        Relationships: [
          {
            foreignKeyName: "calls_conversation_id_fkey"
            columns: ["conversation_id"]
            isOneToOne: false
            referencedRelation: "conversations"
            referencedColumns: ["id"]
          },
        ]
      }
      conversation_members: {
        Row: {
          conversation_id: string
          joined_at: string
          role: string
          user_id: string
        }
        Insert: {
          conversation_id: string
          joined_at?: string
          role?: string
          user_id: string
        }
        Update: {
          conversation_id?: string
          joined_at?: string
          role?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "conversation_members_conversation_id_fkey"
            columns: ["conversation_id"]
            isOneToOne: false
            referencedRelation: "conversations"
            referencedColumns: ["id"]
          },
        ]
      }
      conversations: {
        Row: {
          created_at: string
          created_by: string
          id: string
          title: string
        }
        Insert: {
          created_at?: string
          created_by: string
          id?: string
          title: string
        }
        Update: {
          created_at?: string
          created_by?: string
          id?: string
          title?: string
        }
        Relationships: []
      }
      devices: {
        Row: {
          created_at: string
          fingerprint: string
          id: string
          key_rotated_at: string | null
          key_version: number
          last_seen_at: string
          name: string
          public_identity_key: string
          revoked_at: string | null
          user_id: string
          verification: Database["public"]["Enums"]["device_verification"]
        }
        Insert: {
          created_at?: string
          fingerprint: string
          id?: string
          key_rotated_at?: string | null
          key_version?: number
          last_seen_at?: string
          name: string
          public_identity_key: string
          revoked_at?: string | null
          user_id: string
          verification?: Database["public"]["Enums"]["device_verification"]
        }
        Update: {
          created_at?: string
          fingerprint?: string
          id?: string
          key_rotated_at?: string | null
          key_version?: number
          last_seen_at?: string
          name?: string
          public_identity_key?: string
          revoked_at?: string | null
          user_id?: string
          verification?: Database["public"]["Enums"]["device_verification"]
        }
        Relationships: []
      }
      messages: {
        Row: {
          alg: string
          ciphertext: string
          conversation_id: string
          created_at: string
          envelopes: Json
          id: string
          iv: string
          sender_device_id: string
          sender_id: string
        }
        Insert: {
          alg: string
          ciphertext: string
          conversation_id: string
          created_at?: string
          envelopes: Json
          id?: string
          iv: string
          sender_device_id: string
          sender_id: string
        }
        Update: {
          alg?: string
          ciphertext?: string
          conversation_id?: string
          created_at?: string
          envelopes?: Json
          id?: string
          iv?: string
          sender_device_id?: string
          sender_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "messages_conversation_id_fkey"
            columns: ["conversation_id"]
            isOneToOne: false
            referencedRelation: "conversations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "messages_sender_device_id_fkey"
            columns: ["sender_device_id"]
            isOneToOne: false
            referencedRelation: "devices"
            referencedColumns: ["id"]
          },
        ]
      }
      profiles: {
        Row: {
          created_at: string
          display_name: string
          handle: string
          id: string
        }
        Insert: {
          created_at?: string
          display_name: string
          handle: string
          id: string
        }
        Update: {
          created_at?: string
          display_name?: string
          handle?: string
          id?: string
        }
        Relationships: []
      }
      rate_limits: {
        Row: {
          bucket: string
          count: number
          user_id: string
          window_start: string
        }
        Insert: {
          bucket: string
          count?: number
          user_id: string
          window_start: string
        }
        Update: {
          bucket?: string
          count?: number
          user_id?: string
          window_start?: string
        }
        Relationships: []
      }
      security_events: {
        Row: {
          created_at: string
          detail: Json
          event_type: string
          id: number
          user_id: string
        }
        Insert: {
          created_at?: string
          detail?: Json
          event_type: string
          id?: never
          user_id: string
        }
        Update: {
          created_at?: string
          detail?: Json
          event_type?: string
          id?: never
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      add_member_by_handle: {
        Args: { _conv: string; _handle: string }
        Returns: undefined
      }
      check_rate_limit: {
        Args: { _bucket: string; _max: number; _window_seconds: number }
        Returns: boolean
      }
      create_conversation: { Args: { _title: string }; Returns: string }
      is_member: { Args: { _conv: string; _uid: string }; Returns: boolean }
      log_security_event: {
        Args: { _detail?: Json; _type: string }
        Returns: undefined
      }
      mark_device_verified: { Args: { _device: string }; Returns: undefined }
      revoke_device: { Args: { _device: string }; Returns: undefined }
      rotate_device_key: {
        Args: { _device: string; _fingerprint: string; _public_key: string }
        Returns: undefined
      }
      set_ai_consent: {
        Args: { _conv: string; _granted: boolean }
        Returns: undefined
      }
      update_call_status: {
        Args: { _call: string; _status: Database["public"]["Enums"]["call_status"] }
        Returns: undefined
      }
      shares_conversation: {
        Args: { _a: string; _b: string }
        Returns: boolean
      }
      write_security_event: {
        Args: { _detail: Json; _type: string; _uid: string }
        Returns: undefined
      }
    }
    Enums: {
      call_status: "ringing" | "active" | "ended" | "missed" | "failed"
      device_verification: "unverified" | "verified"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      call_status: ["ringing", "active", "ended", "missed", "failed"],
      device_verification: ["unverified", "verified"],
    },
  },
} as const