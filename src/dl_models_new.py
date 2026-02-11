"""
Deep Learning Models for URL Sequence Learning

Implements:
1. Character-Level CNN
2. Bidirectional LSTM
3. Transformer Encoder

All models learn from RAW URL strings (no handcrafted features)
"""

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model
import numpy as np
from typing import List


class CharCNN:
    """
    Character-Level Convolutional Neural Network
    
    Learns local character n-grams (e.g., "payp"+"al", "acc0unt")
    """
    
    def __init__(
        self,
        vocab_size: int,
        max_length: int = 200,
        embedding_dim: int = 64,
        filters: List[int] = [128, 256, 512],
        kernel_sizes: List[int] = [3, 4, 5],
        dropout_rate: float = 0.5
    ):
        """
        Args:
            vocab_size: Size of character vocabulary
            max_length: Maximum URL length
            embedding_dim: Dimension of character embeddings
            filters: Number of filters for each conv layer
            kernel_sizes: Kernel sizes for multi-scale convolution
            dropout_rate: Dropout rate for regularization
        """
        self.vocab_size = vocab_size
        self.max_length = max_length
        self.embedding_dim = embedding_dim
        self.filters = filters
        self.kernel_sizes = kernel_sizes
        self.dropout_rate = dropout_rate
        
        self.model = self._build_model()
    
    def _build_model(self) -> Model:
        """Build Char-CNN architecture"""
        
        inputs = layers.Input(shape=(self.max_length,), name='input')
        
        # Character embedding
        x = layers.Embedding(
            input_dim=self.vocab_size,
            output_dim=self.embedding_dim,
            input_length=self.max_length,
            name='embedding'
        )(inputs)
        
        # Multi-scale convolution (different kernel sizes)
        conv_blocks = []
        for i, (n_filters, kernel_size) in enumerate(zip(self.filters, self.kernel_sizes)):
            conv = layers.Conv1D(
                filters=n_filters,
                kernel_size=kernel_size,
                activation='relu',
                name=f'conv_{kernel_size}'
            )(x)
            pool = layers.GlobalMaxPooling1D(name=f'pool_{kernel_size}')(conv)
            conv_blocks.append(pool)
        
        # Concatenate all conv outputs
        if len(conv_blocks) > 1:
            x = layers.Concatenate(name='concat')(conv_blocks)
        else:
            x = conv_blocks[0]
        
        # Dense layers
        x = layers.Dense(256, activation='relu', name='dense1')(x)
        x = layers.Dropout(self.dropout_rate, name='dropout1')(x)
        x = layers.Dense(128, activation='relu', name='dense2')(x)
        x = layers.Dropout(self.dropout_rate, name='dropout2')(x)
        
        # Output
        outputs = layers.Dense(1, activation='sigmoid', name='output')(x)
        
        model = Model(inputs=inputs, outputs=outputs, name='CharCNN')
        
        return model
    
    def compile_model(
        self,
        learning_rate: float = 0.001,
        class_weight_ratio: float = 10.0
    ):
        """
        Compile model with cost-sensitive loss
        
        Args:
            learning_rate: Learning rate for optimizer
            class_weight_ratio: Weight ratio for phishing class (FN cost)
        """
        # Cost-sensitive loss (penalize FN more than FP)
        def weighted_binary_crossentropy(y_true, y_pred):
            # FN_cost = 10, FP_cost = 1
            # Cast to float32 to avoid type errors
            y_true = tf.cast(y_true, tf.float32)
            y_pred = tf.cast(y_pred, tf.float32)
            weights = y_true * tf.constant(class_weight_ratio, dtype=tf.float32) + (1.0 - y_true) * 1.0
            bce = keras.backend.binary_crossentropy(y_true, y_pred)
            return keras.backend.mean(bce * weights)
        
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
            loss=weighted_binary_crossentropy,
            metrics=[
                'accuracy',
                keras.metrics.Precision(name='precision'),
                keras.metrics.Recall(name='recall'),
                keras.metrics.AUC(name='auc')
            ]
        )
    
    def summary(self):
        """Print model summary"""
        return self.model.summary()


class BiLSTM:
    """
    Bidirectional LSTM
    
    Learns sequential dependencies in URL structure
    """
    
    def __init__(
        self,
        vocab_size: int,
        max_length: int = 200,
        embedding_dim: int = 128,
        lstm_units: List[int] = [128, 64],
        dropout_rate: float = 0.5,
        recurrent_dropout: float = 0.2
    ):
        self.vocab_size = vocab_size
        self.max_length = max_length
        self.embedding_dim = embedding_dim
        self.lstm_units = lstm_units
        self.dropout_rate = dropout_rate
        self.recurrent_dropout = recurrent_dropout
        
        self.model = self._build_model()
    
    def _build_model(self) -> Model:
        """Build BiLSTM architecture"""
        
        inputs = layers.Input(shape=(self.max_length,), name='input')
        
        # Character embedding
        x = layers.Embedding(
            input_dim=self.vocab_size,
            output_dim=self.embedding_dim,
            input_length=self.max_length,
            name='embedding'
        )(inputs)
        
        # Stacked BiLSTM layers
        for i, units in enumerate(self.lstm_units):
            return_sequences = (i < len(self.lstm_units) - 1)
            
            x = layers.Bidirectional(
                layers.LSTM(
                    units=units,
                    return_sequences=return_sequences,
                    dropout=self.dropout_rate,
                    recurrent_dropout=self.recurrent_dropout,
                    name=f'lstm_{i}'
                ),
                name=f'bilstm_{i}'
            )(x)
        
        # Dense layers
        x = layers.Dense(128, activation='relu', name='dense1')(x)
        x = layers.Dropout(self.dropout_rate, name='dropout')(x)
        x = layers.Dense(64, activation='relu', name='dense2')(x)
        
        # Output
        outputs = layers.Dense(1, activation='sigmoid', name='output')(x)
        
        model = Model(inputs=inputs, outputs=outputs, name='BiLSTM')
        
        return model
    
    def compile_model(self, learning_rate: float = 0.001, class_weight_ratio: float = 10.0):
        """Compile with cost-sensitive loss"""
        def weighted_binary_crossentropy(y_true, y_pred):
            # Cast to float32 to avoid type errors
            y_true = tf.cast(y_true, tf.float32)
            y_pred = tf.cast(y_pred, tf.float32)
            weights = y_true * tf.constant(class_weight_ratio, dtype=tf.float32) + (1.0 - y_true) * 1.0
            bce = keras.backend.binary_crossentropy(y_true, y_pred)
            return keras.backend.mean(bce * weights)
        
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
            loss=weighted_binary_crossentropy,
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall(), keras.metrics.AUC()]
        )
    
    def summary(self):
        return self.model.summary()


class TransformerBlock(layers.Layer):
    """Transformer encoder block"""
    
    def __init__(self, embed_dim, num_heads, ff_dim, rate=0.1):
        super(TransformerBlock, self).__init__()
        self.att = layers.MultiHeadAttention(num_heads=num_heads, key_dim=embed_dim)
        self.ffn = keras.Sequential([
            layers.Dense(ff_dim, activation="relu"),
            layers.Dense(embed_dim),
        ])
        self.layernorm1 = layers.LayerNormalization(epsilon=1e-6)
        self.layernorm2 = layers.LayerNormalization(epsilon=1e-6)
        self.dropout1 = layers.Dropout(rate)
        self.dropout2 = layers.Dropout(rate)
    
    def call(self, inputs, training):
        attn_output = self.att(inputs, inputs)
        attn_output = self.dropout1(attn_output, training=training)
        out1 = self.layernorm1(inputs + attn_output)
        ffn_output = self.ffn(out1)
        ffn_output = self.dropout2(ffn_output, training=training)
        return self.layernorm2(out1 + ffn_output)


class URLTransformer:
    """
    Transformer Encoder for URL Classification
    
    Learns long-range dependencies (e.g., subdomain-TLD mismatch)
    """
    
    def __init__(
        self,
        vocab_size: int,
        max_length: int = 200,
        embedding_dim: int = 128,
        num_heads: int = 8,
        ff_dim: int = 256,
        num_transformer_blocks: int = 2,
        dropout_rate: float = 0.5
    ):
        self.vocab_size = vocab_size
        self.max_length = max_length
        self.embedding_dim = embedding_dim
        self.num_heads = num_heads
        self.ff_dim = ff_dim
        self.num_transformer_blocks = num_transformer_blocks
        self.dropout_rate = dropout_rate
        
        self.model = self._build_model()
    
    def _build_model(self) -> Model:
        """Build Transformer architecture"""
        
        inputs = layers.Input(shape=(self.max_length,), name='input')
        
        # Embedding + positional encoding
        x = layers.Embedding(
            input_dim=self.vocab_size,
            output_dim=self.embedding_dim,
            input_length=self.max_length,
            name='embedding'
        )(inputs)
        
        # Positional encoding
        positions = tf.range(start=0, limit=self.max_length, delta=1)
        position_embedding = layers.Embedding(
            input_dim=self.max_length,
            output_dim=self.embedding_dim,
            name='position_embedding'
        )(positions)
        
        x = x + position_embedding
        
        # Stacked transformer blocks
        for i in range(self.num_transformer_blocks):
            x = TransformerBlock(
                embed_dim=self.embedding_dim,
                num_heads=self.num_heads,
                ff_dim=self.ff_dim,
                rate=self.dropout_rate
            )(x)
        
        # Global pooling
        x = layers.GlobalAveragePooling1D(name='global_pool')(x)
        
        # Dense layers
        x = layers.Dense(128, activation='relu', name='dense1')(x)
        x = layers.Dropout(self.dropout_rate, name='dropout')(x)
        x = layers.Dense(64, activation='relu', name='dense2')(x)
        
        # Output
        outputs = layers.Dense(1, activation='sigmoid', name='output')(x)
        
        model = Model(inputs=inputs, outputs=outputs, name='URLTransformer')
        
        return model
    
    def compile_model(self, learning_rate: float = 0.0001, class_weight_ratio: float = 10.0):
        """Compile with cost-sensitive loss"""
        def weighted_binary_crossentropy(y_true, y_pred):
            # Cast to float32 to avoid type errors
            y_true = tf.cast(y_true, tf.float32)
            y_pred = tf.cast(y_pred, tf.float32)
            weights = y_true * tf.constant(class_weight_ratio, dtype=tf.float32) + (1.0 - y_true) * 1.0
            bce = keras.backend.binary_crossentropy(y_true, y_pred)
            return keras.backend.mean(bce * weights)
        
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
            loss=weighted_binary_crossentropy,
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall(), keras.metrics.AUC()]
        )
    
    def summary(self):
        return self.model.summary()


if __name__ == "__main__":
    print("="*60)
    print("DEEP LEARNING MODELS ARCHITECTURE")
    print("="*60)
    
    vocab_size = 128
    max_length = 200
    
    # 1. Char-CNN
    print("\n[1] Character-Level CNN")
    print("-" * 60)
    char_cnn = CharCNN(
        vocab_size=vocab_size,
        max_length=max_length,
        filters=[128, 256, 512],
        kernel_sizes=[3, 4, 5]
    )
    char_cnn.compile_model()
    char_cnn.summary()
    
    # 2. BiLSTM
    print("\n[2] Bidirectional LSTM")
    print("-" * 60)
    bilstm = BiLSTM(
        vocab_size=vocab_size,
        max_length=max_length,
        lstm_units=[128, 64]
    )
    bilstm.compile_model()
    bilstm.summary()
    
    # 3. Transformer
    print("\n[3] Transformer Encoder")
    print("-" * 60)
    transformer = URLTransformer(
        vocab_size=vocab_size,
        max_length=max_length,
        num_heads=8,
        num_transformer_blocks=2
    )
    transformer.compile_model()
    transformer.summary()
