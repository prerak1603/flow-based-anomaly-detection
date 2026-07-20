"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 07_wgan_gp.py
Description : WGAN-GP synthetic sample generation for rare attack classes
Author      : Prerak Nain
Version     : 2.0.0

--------------------------------------------------------------------------------
PURPOSE
--------------------------------------------------------------------------------
Trains a Wasserstein GAN with Gradient Penalty on SMOTE-boosted rare class
data (Heartbleed, Infiltration) to generate additional, more diverse
synthetic samples than SMOTE interpolation alone can provide.
================================================================================
"""

import sys
import logging
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler


# ==============================================================================
# CONFIGURATION
# ==============================================================================

class Config:
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    RESULTS_DIR  = PROJECT_ROOT / "v2" / "results"
    
    SMOTE_TRAIN_FILE = RESULTS_DIR / "train_data_smote.parquet"
    GAN_OUTPUT_FILE  = RESULTS_DIR / "train_data_gan_augmented.parquet"
    
    LABEL_COLUMN = "Label"
    TARGET_CLASSES = ["Heartbleed", "Infiltration"]
    
    # How many ADDITIONAL synthetic samples to generate per class
    SAMPLES_TO_GENERATE = {
        "Heartbleed": 300,
        "Infiltration": 300
    }
    
    # WGAN-GP hyperparameters
    LATENT_DIM       = 32      # size of random noise input to Generator
    HIDDEN_DIM       = 64
    N_CRITIC         = 5       # train Discriminator 5x per Generator update
    GP_WEIGHT        = 10.0    # gradient penalty coefficient
    LEARNING_RATE    = 0.0001
    BATCH_SIZE       = 16      # small, since we have limited real data
    EPOCHS           = 500
    
    RANDOM_STATE = 42
    LINE_WIDTH   = 80

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ==============================================================================
# LOGGING
# ==============================================================================

def setup_logger():
    logger = logging.getLogger("AegisAI.WGAN")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%H:%M:%S"))
        logger.addHandler(h)
    return logger

log = setup_logger()

def print_header(t):
    print(f"\n{'='*Config.LINE_WIDTH}\n {t}\n{'='*Config.LINE_WIDTH}")

def print_subheader(t):
    print(f"\n{'-'*Config.LINE_WIDTH}\n {t}\n{'-'*Config.LINE_WIDTH}")


# ==============================================================================
# MODEL DEFINITIONS
# ==============================================================================

class Generator(nn.Module):
    """Takes random noise, outputs a synthetic feature vector."""
    
    def __init__(self, latent_dim, feature_dim, hidden_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, feature_dim)
        )
    
    def forward(self, z):
        return self.net(z)


class Critic(nn.Module):
    """
    (Called 'Critic' not 'Discriminator' in WGAN terminology,
    since it outputs a raw score, not a probability.)
    """
    
    def __init__(self, feature_dim, hidden_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(feature_dim, hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_dim, 1)   # single real-valued score, no sigmoid
        )
    
    def forward(self, x):
        return self.net(x)


# ==============================================================================
# GRADIENT PENALTY
# ==============================================================================

def compute_gradient_penalty(critic, real_samples, fake_samples):
    """
    Enforces the 1-Lipschitz constraint by penalizing the Critic's
    gradient norm away from 1, on points interpolated between real
    and fake samples.
    """
    batch_size = real_samples.size(0)
    
    # Random interpolation factor per sample
    alpha = torch.rand(batch_size, 1, device=device)
    interpolates = (alpha * real_samples + (1 - alpha) * fake_samples).requires_grad_(True)
    
    critic_interpolates = critic(interpolates)
    
    gradients = torch.autograd.grad(
        outputs=critic_interpolates,
        inputs=interpolates,
        grad_outputs=torch.ones_like(critic_interpolates),
        create_graph=True,
        retain_graph=True
    )[0]
    
    gradient_norm = gradients.norm(2, dim=1)
    penalty = ((gradient_norm - 1) ** 2).mean()
    
    return penalty


# ==============================================================================
# TRAINING FOR ONE CLASS
# ==============================================================================

def train_wgan_for_class(class_data: np.ndarray, class_name: str, feature_dim: int):
    """Train a WGAN-GP on real samples of ONE specific rare class."""
    
    print_subheader(f"TRAINING WGAN-GP: {class_name}")
    log.info(f"Real samples available: {len(class_data)}")
    
    # Scale to [-1, 1] roughly (helps GAN training stability)
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(class_data)
    
    tensor_data = torch.FloatTensor(scaled_data).to(device)
    dataset = TensorDataset(tensor_data)
    loader = DataLoader(dataset, batch_size=min(Config.BATCH_SIZE, len(class_data)), shuffle=True)
    
    generator = Generator(Config.LATENT_DIM, feature_dim, Config.HIDDEN_DIM).to(device)
    critic = Critic(feature_dim, Config.HIDDEN_DIM).to(device)
    
    opt_g = optim.Adam(generator.parameters(), lr=Config.LEARNING_RATE, betas=(0.5, 0.9))
    opt_c = optim.Adam(critic.parameters(), lr=Config.LEARNING_RATE, betas=(0.5, 0.9))
    
    for epoch in range(Config.EPOCHS):
        for real_batch, in loader:
            batch_size = real_batch.size(0)
            
            # ---- Train Critic N_CRITIC times ----
            for _ in range(Config.N_CRITIC):
                z = torch.randn(batch_size, Config.LATENT_DIM, device=device)
                fake_batch = generator(z).detach()
                
                critic_real = critic(real_batch).mean()
                critic_fake = critic(fake_batch).mean()
                gp = compute_gradient_penalty(critic, real_batch, fake_batch)
                
                critic_loss = -critic_real + critic_fake + Config.GP_WEIGHT * gp
                
                opt_c.zero_grad()
                critic_loss.backward()
                opt_c.step()
            
            # ---- Train Generator once ----
            z = torch.randn(batch_size, Config.LATENT_DIM, device=device)
            fake_batch = generator(z)
            gen_loss = -critic(fake_batch).mean()
            
            opt_g.zero_grad()
            gen_loss.backward()
            opt_g.step()
        
        if (epoch + 1) % 100 == 0:
            print(f"  Epoch {epoch+1}/{Config.EPOCHS} | "
                  f"Critic loss: {critic_loss.item():.4f} | "
                  f"Gen loss: {gen_loss.item():.4f}")
    
    log.info(f"Training complete for {class_name}")
    return generator, scaler


def generate_synthetic_samples(generator, scaler, n_samples, feature_dim):
    """Use trained Generator to produce new synthetic samples."""
    generator.eval()
    with torch.no_grad():
        z = torch.randn(n_samples, Config.LATENT_DIM, device=device)
        synthetic_scaled = generator(z).cpu().numpy()
    
    # Reverse the scaling to get back to original feature ranges
    synthetic = scaler.inverse_transform(synthetic_scaled)
    return synthetic


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def main():
    start = datetime.now()
    print_header("AEGIS AI v2 - WGAN-GP AUGMENTATION")
    print(f" Device: {device}")
    
    try:
        log.info(f"Loading: {Config.SMOTE_TRAIN_FILE}")
        df = pd.read_parquet(Config.SMOTE_TRAIN_FILE, engine='fastparquet')
        
        feature_cols = [c for c in df.columns if c != Config.LABEL_COLUMN]
        feature_dim = len(feature_cols)
        print(f" Feature dimension: {feature_dim}")
        
        all_synthetic_dfs = []
        
        for class_name in Config.TARGET_CLASSES:
            class_df = df[df[Config.LABEL_COLUMN] == class_name]
            class_data = class_df[feature_cols].values
            
            generator, scaler = train_wgan_for_class(class_data, class_name, feature_dim)
            
            n_to_generate = Config.SAMPLES_TO_GENERATE[class_name]
            synthetic = generate_synthetic_samples(generator, scaler, n_to_generate, feature_dim)
            
            synthetic_df = pd.DataFrame(synthetic, columns=feature_cols)
            synthetic_df[Config.LABEL_COLUMN] = class_name
            all_synthetic_dfs.append(synthetic_df)
            
            print(f"\n  Generated {n_to_generate} synthetic {class_name} samples")
        
        # Combine original SMOTE data + new GAN synthetic samples
        gan_synthetic_combined = pd.concat(all_synthetic_dfs, ignore_index=True)
        final_df = pd.concat([df, gan_synthetic_combined], ignore_index=True)
        
        final_df.to_parquet(Config.GAN_OUTPUT_FILE, engine='fastparquet', index=False)
        
        print_header("WGAN-GP COMPLETE")
        print(f" Final training set: {len(final_df):,} records")
        print(f" Saved: {Config.GAN_OUTPUT_FILE.name}")
        
        final_counts = final_df[Config.LABEL_COLUMN].value_counts()
        for cls in Config.TARGET_CLASSES:
            print(f" {cls}: {final_counts.get(cls, 0):,} total samples")
        
        elapsed = (datetime.now() - start).total_seconds()
        print(f"\n Time: {elapsed:.1f}s")
        print(f"{'='*Config.LINE_WIDTH}\n")
        return 0
    
    except Exception as e:
        log.error(f"Failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())