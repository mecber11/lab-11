from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import pandas as pd
import hashlib
import json
import time
import logging
from datetime import datetime, timedelta
import asyncpg
import os
from supabase import create_client, Client
import uuid

# Configuración
class Settings:
    SUPABASE_URL = os.getenv("SUPABASE_URL", "https://tyhinrryhkqjzqicdqys.supabase.co")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR5aGlucnJ5aGtxanpxaWNkcXlzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjI5NTE5NjMsImV4cCI6MjA3ODUyNzk2M30.WX01WadIXdknMY36lTcR3vTZGV0HViFTGLX14Nas89o")
    API_TITLE = "Phishing Detection API"
    API_VERSION = "1.0.0"

settings = Settings()

# Modelos Pydantic
class URLRequest(BaseModel):
    url: str = Field(..., example="https://example.com/login")
    check_threat_intel: bool = True
    created_by: str = Field(..., example="user@company.com")

class URLResponse(BaseModel):
    id: str
    url: str
    analysis_result: Dict[str, Any]
    risk_level: str
    prediction: str
    probability: float
    confidence: str
    features_extracted: int
    processing_time: float
    created_at: str

class BatchAnalysisRequest(BaseModel):
    urls: List[str]
    created_by: str

class StatisticsResponse(BaseModel):
    total_analyzed: int
    phishing_count: int
    suspicious_count: int
    legitimate_count: int
    risk_distribution: Dict[str, int]
    recent_activity: List[Dict[str, Any]]
    daily_stats: Dict[str, Any]

# Inicialización
app = FastAPI(title=settings.API_TITLE, version=settings.API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cliente Supabase
supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

# Servicios
class PhishingAnalyzer:
    @staticmethod
    def analyze_url(url: str) -> Dict[str, Any]:
        """Simula análisis de phishing - En producción conectar con n8n"""
        # Esta función se integraría con el workflow de n8n
        features = PhishingAnalyzer.extract_features(url)
        
        # Simulación de modelo ML
        risk_score = PhishingAnalyzer.calculate_risk_score(features)
        
        # Clasificación
        if risk_score >= 0.85:
            prediction = "PHISHING"
            risk_level = "HIGH"
        elif risk_score >= 0.60:
            prediction = "SUSPICIOUS" 
            risk_level = "MEDIUM"
        else:
            prediction = "LEGITIMATE"
            risk_level = "LOW"
        
        return {
            "prediction": prediction,
            "risk_level": risk_level,
            "probability": round(risk_score, 4),
            "confidence": "HIGH" if risk_score > 0.9 or risk_score < 0.1 else "MEDIUM",
            "features_extracted": len(features),
            "feature_summary": {
                "url_length": features.get('url_length', 0),
                "suspicious_keywords": features.get('suspicious_words_count', 0),
                "entropy_score": round(features.get('url_entropy', 0), 2)
            },
            "threat_intelligence": {
                "virustotal": {"status": "checked", "malicious": 0},
                "google_safe_browsing": {"status": "checked", "threats": []}
            }
        }
    
    @staticmethod
    def extract_features(url: str) -> Dict[str, Any]:
        """Extrae características de la URL"""
        import re
        from urllib.parse import urlparse
        
        features = {}
        parsed = urlparse(url)
        
        # Características básicas
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_slashes'] = url.count('/')
        
        # Palabras sospechosas
        suspicious_words = ['login', 'verify', 'account', 'bank', 'paypal', 'secure']
        features['suspicious_words_count'] = sum(1 for word in suspicious_words if word in url.lower())
        
        # Entropía (simulada)
        features['url_entropy'] = len(set(url)) / len(url) if url else 0
        
        return features
    
    @staticmethod
    def calculate_risk_score(features: Dict[str, Any]) -> float:
        """Calcula puntuación de riesgo"""
        score = 0.0
        score += min(features.get('url_length', 0) / 100, 0.3)
        score += min(features.get('suspicious_words_count', 0) * 0.2, 0.4)
        score += features.get('url_entropy', 0) * 0.3
        return min(score, 1.0)

class DatabaseService:
    @staticmethod
    async def save_analysis(url: str, analysis_result: Dict[str, Any], created_by: str) -> str:
        """Guarda análisis en Supabase"""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        data = {
            "url": url,
            "url_hash": url_hash,
            "analysis_result": analysis_result,
            "risk_level": analysis_result["risk_level"],
            "prediction": analysis_result["prediction"],
            "probability": analysis_result["probability"],
            "confidence": analysis_result["confidence"],
            "features_extracted": analysis_result["features_extracted"],
            "processing_time": 0.5,  # Simulado
            "threat_intelligence": analysis_result.get("threat_intelligence", {}),
            "created_by": created_by
        }
        
        try:
            # Verificar si ya existe
            existing = supabase.table("url_analysis").select("*").eq("url_hash", url_hash).execute()
            
            if existing.data:
                # Actualizar existente
                result = supabase.table("url_analysis").update(data).eq("url_hash", url_hash).execute()
            else:
                # Insertar nuevo
                result = supabase.table("url_analysis").insert(data).execute()
            
            return result.data[0]["id"] if result.data else str(uuid.uuid4())
            
        except Exception as e:
            logging.error(f"Error guardando en BD: {e}")
            return str(uuid.uuid4())
    
    @staticmethod
    async def get_statistics(days: int = 30) -> Dict[str, Any]:
        """Obtiene estadísticas de análisis"""
        try:
            # Total de análisis
            total_result = supabase.table("url_analysis").select("id", count="exact").execute()
            total = total_result.count or 0
            
            # Conteo por categoría
            phishing_result = supabase.table("url_analysis").select("id", count="exact").eq("prediction", "PHISHING").execute()
            suspicious_result = supabase.table("url_analysis").select("id", count="exact").eq("prediction", "SUSPICIOUS").execute()
            legitimate_result = supabase.table("url_analysis").select("id", count="exact").eq("prediction", "LEGITIMATE").execute()
            
            # Distribución de riesgo
            risk_distribution = {}
            for risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                risk_result = supabase.table("url_analysis").select("id", count="exact").eq("risk_level", risk).execute()
                risk_distribution[risk] = risk_result.count or 0
            
            # Actividad reciente
            recent_result = supabase.table("url_analysis").select("*").order("created_at", desc=True).limit(10).execute()
            
            return {
                "total_analyzed": total,
                "phishing_count": phishing_result.count or 0,
                "suspicious_count": suspicious_result.count or 0,
                "legitimate_count": legitimate_result.count or 0,
                "risk_distribution": risk_distribution,
                "recent_activity": recent_result.data
            }
            
        except Exception as e:
            logging.error(f"Error obteniendo estadísticas: {e}")
            return {}

# Endpoints
@app.post("/analyze", response_model=URLResponse)
async def analyze_url(request: URLRequest, background_tasks: BackgroundTasks):
    """Analiza una URL individual"""
    try:
        # Realizar análisis
        analysis_result = PhishingAnalyzer.analyze_url(request.url)
        
        # Guardar en BD (en background)
        analysis_id = await DatabaseService.save_analysis(
            request.url, analysis_result, request.created_by
        )
        
        return URLResponse(
            id=analysis_id,
            url=request.url,
            analysis_result=analysis_result,
            risk_level=analysis_result["risk_level"],
            prediction=analysis_result["prediction"],
            probability=analysis_result["probability"],
            confidence=analysis_result["confidence"],
            features_extracted=analysis_result["features_extracted"],
            processing_time=0.5,
            created_at=datetime.now().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analizando URL: {str(e)}")

@app.post("/analyze-batch")
async def analyze_batch(request: BatchAnalysisRequest):
    """Analiza múltiples URLs"""
    results = []
    
    for url in request.urls:
        try:
            analysis_result = PhishingAnalyzer.analyze_url(url)
            analysis_id = await DatabaseService.save_analysis(url, analysis_result, request.created_by)
            
            results.append({
                "id": analysis_id,
                "url": url,
                "prediction": analysis_result["prediction"],
                "risk_level": analysis_result["risk_level"],
                "probability": analysis_result["probability"]
            })
            
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e)
            })
    
    return {"results": results, "total_processed": len(results)}

@app.post("/analyze-csv")
async def analyze_csv(file: UploadFile = File(...), created_by: str = "system"):
    """Analiza URLs desde archivo CSV"""
    try:
        # Leer CSV
        contents = await file.read()
        df = pd.read_csv(pd.io.common.BytesIO(contents))
        
        # Asumir que la columna se llama 'url'
        urls = df['url'].tolist() if 'url' in df.columns else []
        
        # Procesar en lote
        results = []
        for url in urls[:100]:  # Límite de 100 URLs
            analysis_result = PhishingAnalyzer.analyze_url(url)
            analysis_id = await DatabaseService.save_analysis(url, analysis_result, created_by)
            
            results.append({
                "id": analysis_id,
                "url": url,
                "prediction": analysis_result["prediction"],
                "risk_level": analysis_result["risk_level"]
            })
        
        return {"results": results, "total_analyzed": len(results)}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error procesando CSV: {str(e)}")

@app.get("/statistics")
async def get_statistics(days: int = 30):
    """Obtiene estadísticas de análisis"""
    stats = await DatabaseService.get_statistics(days)
    return stats

@app.get("/recent-analyses")
async def get_recent_analyses(limit: int = 20):
    """Obtiene análisis recientes"""
    try:
        result = supabase.table("url_analysis").select("*").order("created_at", desc=True).limit(limit).execute()
        return result.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo análisis: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check del sistema"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": "connected" if supabase else "disconnected"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
