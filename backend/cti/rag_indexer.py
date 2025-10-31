"""
RAG indexer for CTI data in SENTRIX LIVE++.
Creates and manages vector embeddings for threat intelligence data.
"""
import logging
import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from langchain.vectorstores import FAISS
from langchain.embeddings import OpenAIEmbeddings
from langchain.schema import Document

from backend.core.config import settings
from backend.core.db import get_elasticsearch_client

logger = logging.getLogger(__name__)

class CTIRAGIndexer:
    """RAG indexer for CTI data."""
    
    def __init__(self):
        """Initialize the RAG indexer."""
        self.es_client = get_elasticsearch_client()
        self.embeddings = OpenAIEmbeddings(
            openai_api_key=settings.llm.OPENAI_API_KEY
        )
        self.vector_store_path = os.path.join(
            settings.llm.VECTOR_STORE_DIR, 
            "cti_faiss_index"
        )
        
        # Create vector store directory if it doesn't exist
        os.makedirs(settings.llm.VECTOR_STORE_DIR, exist_ok=True)
    
    def index_cti_data(self) -> int:
        """Index CTI data from Elasticsearch to FAISS."""
        try:
            # Get CTI data from Elasticsearch
            cti_data = self._get_cti_data()
            
            if not cti_data:
                logger.warning("No CTI data found to index")
                return 0
            
            # Convert to documents
            documents = self._convert_to_documents(cti_data)
            
            # Create vector store
            vector_store = FAISS.from_documents(documents, self.embeddings)
            
            # Save vector store
            vector_store.save_local(self.vector_store_path)
            
            logger.info(f"Indexed {len(documents)} CTI documents to FAISS")
            return len(documents)
        
        except Exception as e:
            logger.error(f"Error indexing CTI data: {str(e)}")
            return 0
    
    def _get_cti_data(self) -> List[Dict[str, Any]]:
        """Get CTI data from Elasticsearch."""
        try:
            # Query for all CTI data
            query = {
                "query": {
                    "match_all": {}
                },
                "size": 1000  # Limit to 1000 documents
            }
            
            response = self.es_client.search(
                index=f"{settings.elasticsearch.INDEX_PREFIX}cti",
                body=query
            )
            
            hits = response.get("hits", {}).get("hits", [])
            
            return [hit.get("_source", {}) for hit in hits]
        
        except Exception as e:
            logger.error(f"Error getting CTI data: {str(e)}")
            return []
    
    def _convert_to_documents(self, cti_data: List[Dict[str, Any]]) -> List[Document]:
        """Convert CTI data to documents for indexing."""
        documents = []
        
        for item in cti_data:
            # Extract relevant fields
            content_parts = []
            
            # Add type
            if "type" in item:
                content_parts.append(f"Type: {item['type']}")
            
            # Add name/title
            if "name" in item:
                content_parts.append(f"Name: {item['name']}")
            
            # Add description
            if "description" in item:
                content_parts.append(f"Description: {item['description']}")
            
            # Add pattern for indicators
            if "pattern" in item:
                content_parts.append(f"Pattern: {item['pattern']}")
            
            # Add MITRE ATT&CK specific fields
            if "kill_chain_phases" in item:
                phases = item["kill_chain_phases"]
                if phases and isinstance(phases, list):
                    phases_str = ", ".join([p.get("phase_name", "") for p in phases])
                    content_parts.append(f"Kill Chain Phases: {phases_str}")
            
            # Add external references
            if "external_references" in item:
                refs = item["external_references"]
                if refs and isinstance(refs, list):
                    for ref in refs:
                        if "url" in ref:
                            content_parts.append(f"Reference: {ref.get('source_name', '')}: {ref['url']}")
            
            # Create document content
            content = "\n".join(content_parts)
            
            if content:
                # Create metadata
                metadata = {
                    "id": item.get("id", ""),
                    "type": item.get("type", ""),
                    "source_name": item.get("source_name", ""),
                    "created": item.get("created", "")
                }
                
                # Create document
                doc = Document(
                    page_content=content,
                    metadata=metadata
                )
                
                documents.append(doc)
        
        return documents
    
    def search(self, query: str, k: int = 3) -> List[Document]:
        """Search the vector store for relevant CTI data."""
        try:
            # Load vector store
            if not os.path.exists(self.vector_store_path):
                logger.warning("Vector store not found. Indexing CTI data...")
                self.index_cti_data()
            
            vector_store = FAISS.load_local(
                self.vector_store_path,
                self.embeddings
            )
            
            # Search
            docs = vector_store.similarity_search(query, k=k)
            
            return docs
        
        except Exception as e:
            logger.error(f"Error searching vector store: {str(e)}")
            return []

# Singleton instance
cti_rag_indexer = CTIRAGIndexer()

def get_cti_rag_indexer():
    """Get the CTI RAG indexer instance."""
    return cti_rag_indexer