-- ==============================================================================
-- STARXIS HYBRID AUTHENTICATION & PROFILES SCHEMA FOR SUPABASE
-- High-Performance B2B Mobile Super-App Ecosystem (Bangladesh Market)
-- ==============================================================================

-- 1. Create custom types for user roles and verification statuses
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('buyer', 'seller_owner', 'seller_sales', 'seller_ops');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE verification_status_type AS ENUM ('Unverified', 'Under Review', 'Verified');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 2. Create the `profiles` table linked directly with Supabase `auth.users`
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE,
    phone_number TEXT UNIQUE,
    full_name TEXT,
    avatar_url TEXT,
    role user_role NOT NULL DEFAULT 'buyer',
    store_id TEXT,
    industry TEXT,
    verification_status verification_status_type NOT NULL DEFAULT 'Unverified',
    is_anonymous BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 3. Create Performance Indexes
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_profiles_store_id ON public.profiles(store_id);
CREATE INDEX IF NOT EXISTS idx_profiles_phone ON public.profiles(phone_number);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);

-- 4. Enable Row Level Security (RLS) on `profiles`
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- 5. Define Row Level Security Policies
-- Policy 1: Users can read their own profile, or public store seller profiles
CREATE POLICY "Users can view their own profile" 
ON public.profiles 
FOR SELECT 
USING (
    auth.uid() = id OR 
    (role IN ('seller_owner', 'seller_sales', 'seller_ops') AND verification_status = 'Verified')
);

-- Policy 2: Users can insert their own profile
CREATE POLICY "Users can insert their own profile" 
ON public.profiles 
FOR INSERT 
WITH CHECK (auth.uid() = id);

-- Policy 3: Users can update only their own profile
CREATE POLICY "Users can update their own profile" 
ON public.profiles 
FOR UPDATE 
USING (auth.uid() = id)
WITH CHECK (auth.uid() = id);

-- Policy 4: Users can delete their own profile
CREATE POLICY "Users can delete their own profile" 
ON public.profiles 
FOR DELETE 
USING (auth.uid() = id);

-- 6. PostgreSQL Function to handle new user registration automatically
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER 
SECURITY DEFINER 
SET search_path = public
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO public.profiles (
        id,
        email,
        phone_number,
        full_name,
        avatar_url,
        role,
        is_anonymous,
        verification_status,
        created_at,
        updated_at
    )
    VALUES (
        NEW.id,
        NEW.email,
        NEW.phone,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', ''),
        COALESCE(NEW.raw_user_meta_data->>'avatar_url', ''),
        COALESCE((NEW.raw_user_meta_data->>'role')::user_role, 'buyer'::user_role),
        COALESCE((NEW.raw_app_meta_data->>'provider' = 'anonymous'), false),
        'Unverified'::verification_status_type,
        NOW(),
        NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        phone_number = EXCLUDED.phone_number,
        updated_at = NOW();

    RETURN NEW;
END;
$$;

-- 7. Trigger to execute function on new sign-ups in `auth.users`
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user();

-- 8. Helper Function to link anonymous sessions during 1-tap Google / Phone OTP upgrades
CREATE OR REPLACE FUNCTION public.link_anonymous_session(
    target_role user_role,
    user_email TEXT,
    user_phone TEXT,
    assigned_store_id TEXT DEFAULT NULL
)
RETURNS VOID
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE public.profiles
    SET 
        role = target_role,
        email = COALESCE(user_email, email),
        phone_number = COALESCE(user_phone, phone_number),
        store_id = COALESCE(assigned_store_id, store_id),
        is_anonymous = false,
        updated_at = NOW()
    WHERE id = auth.uid();
END;
$$;
