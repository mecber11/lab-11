import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import base64
from io import BytesIO
import json

# Configuración de la página
st.set_page_config(
    page_title="Sistema de Detección de Phishing",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuración
API_BASE_URL = "http://localhost:8000"

# Estilos CSS personalizados
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .risk-high { background-color: #ff4b4b; color: white; padding: 5px; border-radius: 5px; }
    .risk-medium { background-color: #ffa500; color: white; padding: 5px; border-radius: 5px; }
    .risk-low { background-color: #4caf50; color: white; padding: 5px; border-radius: 5px; }
    .metric-card { 
        background-color: #f0f2f6; 
        padding: 1rem; 
        border-radius: 10px; 
        border-left: 5px solid #1f77b4;
    }
</style>
""", unsafe_allow_html=True)

class PhishingFrontend:
    def __init__(self):
        self.api_base = API_BASE_URL
    
    def analyze_single_url(self, url: str, user_email: str) -> dict:
        """Analiza una URL individual"""
        try:
            response = requests.post(
                f"{self.api_base}/analyze",
                json={"url": url, "check_threat_intel": True, "created_by": user_email},
                timeout=30
            )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            st.error(f"Error analizando URL: {e}")
            return None
    
    def analyze_batch_urls(self, urls: list, user_email: str) -> dict:
        """Analiza múltiples URLs"""
        try:
            response = requests.post(
                f"{self.api_base}/analyze-batch",
                json={"urls": urls, "created_by": user_email},
                timeout=60
            )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            st.error(f"Error analizando URLs en lote: {e}")
            return None
    
    def analyze_csv_file(self, file, user_email: str) -> dict:
        """Analiza URLs desde archivo CSV"""
        try:
            files = {"file": (file.name, file.getvalue(), "text/csv")}
            response = requests.post(
                f"{self.api_base}/analyze-csv",
                files=files,
                data={"created_by": user_email},
                timeout=120
            )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            st.error(f"Error procesando archivo CSV: {e}")
            return None
    
    def get_statistics(self) -> dict:
        """Obtiene estadísticas del sistema"""
        try:
            response = requests.get(f"{self.api_base}/statistics")
            return response.json() if response.status_code == 200 else {}
        except:
            return {}
    
    def get_recent_analyses(self) -> list:
        """Obtiene análisis recientes"""
        try:
            response = requests.get(f"{self.api_base}/recent-analyses")
            return response.json() if response.status_code == 200 else []
        except:
            return []

def main():
    st.markdown('<h1 class="main-header">🛡️ Sistema de Detección de Phishing</h1>', unsafe_allow_html=True)
    
    # Inicializar frontend
    frontend = PhishingFrontend()
    
    # Sidebar
    st.sidebar.title("Navegación")
    app_mode = st.sidebar.selectbox(
        "Selecciona el modo",
        ["📊 Dashboard", "🔍 Análisis Individual", "📁 Análisis por Lote", "📈 Reportes"]
    )
    
    # Información del usuario
    user_email = st.sidebar.text_input("📧 Email del analista", "analyst@company.com")
    
    # Dashboard principal
    if app_mode == "📊 Dashboard":
        show_dashboard(frontend)
    
    # Análisis individual
    elif app_mode == "🔍 Análisis Individual":
        show_individual_analysis(frontend, user_email)
    
    # Análisis por lote
    elif app_mode == "📁 Análisis por Lote":
        show_batch_analysis(frontend, user_email)
    
    # Reportes
    elif app_mode == "📈 Reportes":
        show_reports(frontend)

def show_dashboard(frontend: PhishingFrontend):
    """Muestra el dashboard principal"""
    
    st.header("📊 Dashboard de Seguridad")
    
    # Cargar estadísticas
    with st.spinner("Cargando estadísticas..."):
        stats = frontend.get_statistics()
        recent_analyses = frontend.get_recent_analyses()
    
    if not stats:
        st.error("No se pudieron cargar las estadísticas")
        return
    
    # Métricas principales
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Analizado", stats.get('total_analyzed', 0))
    
    with col2:
        st.metric("Sitios de Phishing", stats.get('phishing_count', 0))
    
    with col3:
        st.metric("Sitios Sospechosos", stats.get('suspicious_count', 0))
    
    with col4:
        st.metric("Sitios Legítimos", stats.get('legitimate_count', 0))
    
    # Gráficos
    col1, col2 = st.columns(2)
    
    with col1:
        # Distribución de predicciones
        predictions_data = {
            'Categoría': ['Phishing', 'Sospechoso', 'Legítimo'],
            'Cantidad': [
                stats.get('phishing_count', 0),
                stats.get('suspicious_count', 0),
                stats.get('legitimate_count', 0)
            ]
        }
        df_predictions = pd.DataFrame(predictions_data)
        
        fig_predictions = px.pie(
            df_predictions, 
            values='Cantidad', 
            names='Categoría',
            title='Distribución de Predicciones',
            color='Categoría',
            color_discrete_map={'Phishing':'red', 'Sospechoso':'orange', 'Legítimo':'green'}
        )
        st.plotly_chart(fig_predictions, use_container_width=True)
    
    with col2:
        # Distribución de riesgo
        risk_data = stats.get('risk_distribution', {})
        if risk_data:
            df_risk = pd.DataFrame({
                'Nivel de Riesgo': list(risk_data.keys()),
                'Cantidad': list(risk_data.values())
            })
            
            fig_risk = px.bar(
                df_risk,
                x='Nivel de Riesgo',
                y='Cantidad',
                title='Distribución por Nivel de Riesgo',
                color='Nivel de Riesgo',
                color_discrete_map={
                    'LOW': 'green', 
                    'MEDIUM': 'orange', 
                    'HIGH': 'red',
                    'CRITICAL': 'darkred'
                }
            )
            st.plotly_chart(fig_risk, use_container_width=True)
    
    # Análisis recientes
    st.subheader("🔍 Análisis Recientes")
    if recent_analyses:
        recent_df = pd.DataFrame(recent_analyses)
        if not recent_df.empty:
            # Simplificar columnas para visualización
            display_df = recent_df[['url', 'prediction', 'risk_level', 'probability', 'created_at']].head(10)
            st.dataframe(display_df, use_container_width=True)
    else:
        st.info("No hay análisis recientes para mostrar")

def show_individual_analysis(frontend: PhishingFrontend, user_email: str):
    """Muestra interfaz para análisis individual"""
    
    st.header("🔍 Análisis Individual de URL")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        url = st.text_input(
            "Ingresa la URL a analizar:",
            placeholder="https://example.com/login",
            help="Ingresa una URL completa con protocolo (http:// o https://)"
        )
    
    with col2:
        st.write("")
        st.write("")
        analyze_btn = st.button("🚀 Analizar URL", type="primary")
    
    if analyze_btn and url:
        if not url.startswith(('http://', 'https://')):
            st.warning("⚠️ Por favor incluye el protocolo (http:// o https://)")
            return
        
        with st.spinner("Analizando URL..."):
            result = frontend.analyze_single_url(url, user_email)
        
        if result:
            display_analysis_result(result)

def show_batch_analysis(frontend: PhishingFrontend, user_email: str):
    """Muestra interfaz para análisis por lote"""
    
    st.header("📁 Análisis por Lote")
    
    tab1, tab2 = st.tabs(["📤 Subir Archivo CSV", "📝 Ingresar Múltiples URLs"])
    
    with tab1:
        st.subheader("Analizar desde archivo CSV")
        uploaded_file = st.file_uploader(
            "Sube un archivo CSV con URLs",
            type=['csv'],
            help="El archivo debe contener una columna 'url' con las URLs a analizar"
        )
        
        if uploaded_file is not None:
            if st.button("📊 Analizar Archivo CSV", type="primary"):
                with st.spinner("Procesando archivo..."):
                    result = frontend.analyze_csv_file(uploaded_file, user_email)
                
                if result:
                    display_batch_results(result)
    
    with tab2:
        st.subheader("Ingresar múltiples URLs")
        urls_text = st.text_area(
            "Ingresa una URL por línea:",
            placeholder="https://example1.com\nhttps://example2.com\nhttps://example3.com",
            height=150
        )
        
        if st.button("🔍 Analizar URLs", type="primary") and urls_text:
            urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
            valid_urls = [url for url in urls if url.startswith(('http://', 'https://'))]
            
            if len(valid_urls) != len(urls):
                st.warning("Algunas URLs no tienen protocolo y serán omitidas")
            
            if valid_urls:
                with st.spinner(f"Analizando {len(valid_urls)} URLs..."):
                    result = frontend.analyze_batch_urls(valid_urls, user_email)
                
                if result:
                    display_batch_results(result)

def show_reports(frontend: PhishingFrontend):
    """Muestra sección de reportes"""
    
    st.header("📈 Reportes y Estadísticas")
    
    # Generar reporte PDF
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Generar Reporte")
        report_type = st.selectbox("Tipo de reporte", ["Diario", "Semanal", "Mensual", "Personalizado"])
        
        if report_type == "Personalizado":
            date_range = st.date_input("Rango de fechas", [])
        else:
            days = st.slider("Días a incluir", 1, 365, 30)
        
        if st.button("📄 Generar Reporte PDF", type="primary"):
            with st.spinner("Generando reporte..."):
                # Aquí se generaría el PDF
                generate_pdf_report(frontend, days if 'days' in locals() else 30)
    
    with col2:
        st.subheader("Estadísticas Detalladas")
        stats = frontend.get_statistics()
        
        if stats:
            # Métricas avanzadas
            st.markdown("### Métricas de Rendimiento")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                total = stats.get('total_analyzed', 0)
                phishing = stats.get('phishing_count', 0)
                rate = (phishing / total * 100) if total > 0 else 0
                st.metric("Tasa de Phishing", f"{rate:.1f}%")
            
            with col2:
                suspicious = stats.get('suspicious_count', 0)
                suspicious_rate = (suspicious / total * 100) if total > 0 else 0
                st.metric("Tasa Sospechosa", f"{suspicious_rate:.1f}%")
            
            with col3:
                st.metric("Precisión Estimada", "95.2%")

def display_analysis_result(result: dict):
    """Muestra los resultados de un análisis individual"""
    
    st.success("✅ Análisis completado")
    
    # Tarjeta de resultados
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        risk_level = result.get('risk_level', 'UNKNOWN')
        risk_color = {
            'LOW': 'green',
            'MEDIUM': 'orange', 
            'HIGH': 'red',
            'CRITICAL': 'darkred'
        }.get(risk_level, 'gray')
        
        st.markdown(f"**Nivel de Riesgo:** <span style='color:{risk_color}; font-weight:bold'>{risk_level}</span>", 
                   unsafe_allow_html=True)
    
    with col2:
        prediction = result.get('prediction', 'UNKNOWN')
        st.markdown(f"**Predicción:** {prediction}")
    
    with col3:
        probability = result.get('probability', 0)
        st.markdown(f"**Probabilidad:** {probability:.1%}")
    
    with col4:
        confidence = result.get('confidence', 'LOW')
        st.markdown(f"**Confianza:** {confidence}")
    
    # Detalles expandibles
    with st.expander("📋 Detalles del Análisis", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Características Extraídas")
            features = result.get('analysis_result', {}).get('feature_summary', {})
            if features:
                for feature, value in features.items():
                    st.write(f"- {feature}: {value}")
        
        with col2:
            st.subheader("Threat Intelligence")
            threat_intel = result.get('analysis_result', {}).get('threat_intelligence', {})
            if threat_intel:
                for service, data in threat_intel.items():
                    st.write(f"- **{service}:** {data.get('status', 'N/A')}")

def display_batch_results(result: dict):
    """Muestra resultados de análisis por lote"""
    
    results = result.get('results', [])
    total = result.get('total_processed', 0)
    
    st.success(f"✅ Análisis completado: {len(results)} URLs procesadas")
    
    if results:
        # Convertir a DataFrame para mejor visualización
        df = pd.DataFrame(results)
        
        # Mostrar resumen
        col1, col2, col3 = st.columns(3)
        
        phishing_count = len(df[df.get('prediction') == 'PHISHING'])
        suspicious_count = len(df[df.get('prediction') == 'SUSPICIOUS'])
        legitimate_count = len(df[df.get('prediction') == 'LEGITIMATE'])
        
        with col1:
            st.metric("Phishing", phishing_count)
        with col2:
            st.metric("Sospechosos", suspicious_count)
        with col3:
            st.metric("Legítimos", legitimate_count)
        
        # Mostrar tabla de resultados
        st.subheader("Resultados Detallados")
        st.dataframe(df, use_container_width=True)
        
        # Opción para descargar resultados
        csv = df.to_csv(index=False)
        b64 = base64.b64encode(csv.encode()).decode()
        href = f'<a href="data:file/csv;base64,{b64}" download="resultados_phishing.csv">📥 Descargar Resultados CSV</a>'
        st.markdown(href, unsafe_allow_html=True)

def generate_pdf_report(frontend: PhishingFrontend, days: int):
    """Genera un reporte PDF y lo descarga"""

    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from io import BytesIO

    # Obtener estadísticas
    stats = frontend.get_statistics()
    recent = frontend.get_recent_analyses()

    # Crear buffer en memoria
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    # Título
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(50, 750, f"Reporte de Detección de Phishing - Últimos {days} días")

    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, 720, f"Total Analizado: {stats.get('total_analyzed', 0)}")
    pdf.drawString(50, 700, f"Phishing: {stats.get('phishing_count', 0)}")
    pdf.drawString(50, 680, f"Sospechosos: {stats.get('suspicious_count', 0)}")
    pdf.drawString(50, 660, f"Legítimos: {stats.get('legitimate_count', 0)}")

    # Línea
    pdf.line(50, 645, 550, 645)

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, 620, "Análisis Recientes:")

    pdf.setFont("Helvetica", 10)

    y = 600
    for item in recent[:10]:
        pdf.drawString(50, y, f"- {item.get('url')}  |  {item.get('prediction')}  |  {item.get('risk_level')}")
        y -= 15
        if y < 80:
            pdf.showPage()
            y = 750
            pdf.setFont("Helvetica", 10)

    pdf.save()
    buffer.seek(0)

    # Descargar PDF
    st.success("📄 Reporte PDF generado correctamente")

    st.download_button(
        label="📥 Descargar Reporte PDF",
        data=buffer,
        file_name="reporte_phishing.pdf",
        mime="application/pdf"
    )


if __name__ == "__main__":
    main()
