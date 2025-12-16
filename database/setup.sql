-- Tabla principal de URLs analizadas
CREATE TABLE IF NOT EXISTS url_analysis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    url_hash VARCHAR(64) UNIQUE NOT NULL,
    analysis_result JSONB NOT NULL,
    risk_level VARCHAR(20) CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    prediction VARCHAR(20) CHECK (prediction IN ('LEGITIMATE', 'SUSPICIOUS', 'PHISHING', 'MALWARE')),
    probability DECIMAL(3,2),
    confidence VARCHAR(10),
    features_extracted INTEGER,
    processing_time DECIMAL(8,4),
    threat_intelligence JSONB,
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tabla de estadísticas y reportes
CREATE TABLE IF NOT EXISTS analysis_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) CHECK (report_type IN ('DAILY', 'WEEKLY', 'MONTHLY', 'CUSTOM')),
    date_range DATERANGE,
    statistics JSONB NOT NULL,
    pdf_report_url TEXT,
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tabla de usuarios/mantenedores
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tabla de configuración del sistema
CREATE TABLE IF NOT EXISTS system_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(255) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    updated_by VARCHAR(255),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Índices para optimización
CREATE INDEX IF NOT EXISTS idx_url_analysis_risk_level ON url_analysis(risk_level);
CREATE INDEX IF NOT EXISTS idx_url_analysis_created_at ON url_analysis(created_at);
CREATE INDEX IF NOT EXISTS idx_url_analysis_url_hash ON url_analysis(url_hash);
CREATE INDEX IF NOT EXISTS idx_analysis_reports_date_range ON analysis_reports(date_range);

-- Triggers para actualización de timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_url_analysis_updated_at BEFORE UPDATE ON url_analysis FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_system_config_updated_at BEFORE UPDATE ON system_config FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Inserción de datos iniciales
INSERT INTO users (email, name, role) VALUES 
('admin@company.com', 'Administrador del Sistema', 'ADMIN'),
('analyst@company.com', 'Analista de Seguridad', 'ANALYST'),
('viewer@company.com', 'Usuario de Consulta', 'VIEWER')
ON CONFLICT (email) DO NOTHING;

INSERT INTO system_config (config_key, config_value, description) VALUES 
('phishing_threshold', '{"value": 0.85}'::JSONB, 'Umbral para clasificación de phishing'),
('suspicious_threshold', '{"value": 0.60}'::JSONB, 'Umbral para clasificación sospechosa'),
('rate_limit', '{"requests_per_minute": 60}'::JSONB, 'Límite de solicitudes por minuto'),
('features_config', '{"enabled_features": ["url_length", "suspicious_keywords", "entropy", "redirects"]}'::JSONB, 'Características habilitadas para análisis')
ON CONFLICT (config_key) DO NOTHING;
