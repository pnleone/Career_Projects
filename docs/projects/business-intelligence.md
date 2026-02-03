# Business Intelligence & Data Analytics

<div class="image-large">
<img src="/Career_Projects/assets/misc/bi-logo.png" alt="BI-Logo">
</div>

End-to-end BI implementation demonstrating data engineering, modeling, and visualization capabilities. Multi-platform architecture spanning SQL Server, Excel Power Query, and Power BI with advanced DAX time intelligence and relational integrity controls.

**Technologies:** SQL Server 2022 Express, Excel Power Query, Power BI Desktop, DAX
    
 

**Skills Matrix**

| Category | Technologies Used | Proficiency Demonstrated |
|----------|-------------------|-------------------------|
| Data Engineering | SQL Server, Power Query ETL | Data modeling, normalization, index optimization |
| Business Intelligence | Power BI, Excel Pivot Tables | Dashboard design, DAX, time intelligence |
| Data Visualization | Power BI visuals, Excel charts | KPI design, interactive filtering, drill-through |
| Programming | DAX, SQL, M (Power Query) | Measure creation, query optimization, data transformation |

---
## Project Overview

Developed comprehensive BI solution using Foodmart sample dataset to demonstrate enterprise-grade data analysis capabilities. Implemented multi-tier architecture with data warehouse design, dimensional modeling, and advanced analytics through DAX measures.

**Key Deliverables:**

- Normalized relational database (SQL Server 2022 Express)
- Excel Power Query ETL pipeline with data model
- Interactive Power BI dashboards with time intelligence
- Advanced DAX measures (MTD/QTD/YTD calculations)

---
### Solution Approach

**Multi-Platform Architecture Rationale:**

Why SQL Server + Excel + Power BI?
Selected complementary tools to address specific stakeholder needs while maintaining single source of truth. Each platform serves distinct user personas with varying technical capabilities.
    

**Technology Stack Justification:**

| Platform | Purpose | User Persona | Key Benefit |
|----------|---------|--------------|-------------|
| **SQL Server 2022 Express** | Data Warehouse | Data Engineers, Analysts | Centralized repository with referential integrity; enables complex joins and aggregations at scale |
| **Excel Power Query** | ETL & Ad-Hoc Analysis | Finance Team, Department Managers | Familiar interface for users with existing Excel skills; Power Query provides code-free ETL for citizen data analysts |
| **Power BI Desktop** | Executive Dashboards | C-Suite, Regional Managers | Self-service BI with drill-down capabilities; mobile access for field managers; real-time KPI monitoring |

**Architecture Benefits:**

1. **SQL Server as Single Source of Truth**
- Centralized storage eliminates data silos
- Enforces referential integrity via foreign key constraints
- Provides audit trail with transaction logging
- Supports concurrent access (10+ simultaneous users)

2. **Excel for Transitional Users**
- Reduces change management friction (familiar tool)
- Power Query enables self-service ETL without coding
- DAX measures provide advanced analytics without leaving Excel
- Offline analysis capability for remote locations

3. **Power BI for Visual Analytics**
- Interactive dashboards reduce time-to-insight from days to minutes
- Mobile app enables field managers to monitor store performance on-the-go
- Natural language Q&A lowers barrier to entry for non-technical users
- Scheduled refresh automates monthly reporting cycles

---

## Technical Implementation

### Data Architecture

**Dataset Scope:**

- **8 tables** (5 dimension lookups, 3 fact tables)
- **1997-1998** transaction data (269.7K transactions)
- **Dimensional model** with star schema design

**Source Tables:**

- **Dimension Tables:** Customers, Products, Regions, Stores, Calendar
- **Fact Tables:** Transactions_1997, Transactions_1998, Returns_1997-1998

<div class="two-col-right">
  <div class="text-col">
    <h4>Data Model Relationships</h4>
    <p>
      Implemented star schema with proper cardinality (1:M), referential integrity via foreign keys, and bidirectional filtering where appropriate. Hidden foreign keys in Excel model for clean visualization while maintaining relationship functionality.
    </p>
    <p>
      <strong>Key Features:</strong> Calculated columns, custom measures, date hierarchies (Year > Quarter > Month > Day), role-playing dimensions (Calendar table).
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/bi-excel-rel.png" alt="Excel Data Model">
      <figcaption>Excel Data Model Relationships</figcaption>
    </figure>
  </div>
</div>

---

### ETL Pipeline (Power Query)

**Transformation Workflow:**
```
CSV Import → Data Profiling → Type Conversion → Calculated Columns → Table Merge → Load
```

**Key Transformations:**

1. **Calendar Enhancement**
   - Original: Single date column
   - Enhanced: Day, Month, Year, Quarter, Fiscal Period, End-of-Month, Weekend/Weekday indicators
   - Purpose: Enable time intelligence analysis

2. **Transaction Consolidation**
   - Merged 1997/1998 transaction tables
   - Standardized data types across years
   - Added calculated columns: Net Revenue, Transaction Month, Quarter

3. **Data Quality**
   - Removed duplicates (0.2% of dataset)
   - Handled null values in Product_Name (filled from Product_ID lookup)
   - Validated foreign key relationships (100% referential integrity)

<div class="two-col-right">
  <div class="text-col">
    <h4>Calendar Dimension Before/After</h4>
    <p>
      <strong>Original:</strong> Basic short date field only.
    </p>
    <p>
      <strong>Enhanced (right):</strong> Full date hierarchy with fiscal periods, end-of-period markers, and day-type classification for advanced temporal analysis.
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/bi-excel-cal.png" alt="Calendar Table Transformation">
      <figcaption>Calendar Table Enhancement</figcaption>
    </figure>
  </div>
</div>

---

### SQL Server Implementation

**Database Design:**

- **RDBMS:** SQL Server 2022 Express
- **Schema:** Normalized star schema (3NF dimension tables, denormalized fact tables)
- **Keys:** Clustered indexes on primary keys, non-clustered on foreign keys
- **Constraints:** FK constraints enforce referential integrity

**Server Configuration:**

- **Edition:** SQL Server 2022 Express (64-bit)
- **Compatibility Level:** 150 (SQL Server 2019)
- **Collation:** SQL_Latin1_General_CP1_CI_AS
- **Recovery Model:** Simple (sufficient for analytics workload; no point-in-time restore required)

**Database Schema:**

Star schema with 5 dimension tables and 2 fact tables. Total row count: 280,201 records across all tables supporting 1997-1998 transactional analysis.

**Table Summary:**

| Table Name | Row Count | Table Type | Purpose |
|------------|-----------|------------|---------|
| Transactions | 269,720 | Fact | Consolidated sales transactions (1997-1998) |
| Customer_Lookup | 10,281 | Dimension | Customer master data with demographics |
| Returns | 7,087 | Fact | Product return records |
| Product_Lookup | 1,560 | Dimension | Product catalog with pricing/attributes |
| Calendar_Lookup | 730 | Dimension | Date dimension (1997-01-01 to 1998-12-31) |
| Region_Lookup | 109 | Dimension | Sales district and region hierarchy |
| Store_Lookup | 24 | Dimension | Store locations with operational details |

---

**Database Diagram:**

<figure>
  <img src="/Career_Projects/assets/diagrams/bi-sql-rel.png" alt="SQL Server Database Diagram">
  <figcaption>SQL Server 2022 Database Relationships</figcaption>
</figure>

### Relational Integrity
#### Foreign Key Relationships
9 foreign key constraints enforce referential integrity between fact and dimension tables. All relationships validated with zero orphaned records.
    
**Foreign Key Constraints:**

| FK Table | FK Column | PK Table | PK Column | Relationship |
|----------|-----------|----------|-----------|--------------|
| Returns | product_id | Product_Lookup | product_id | Many-to-One |
| Returns | return_date | Calendar_Lookup | date | Many-to-One |
| Returns | store_id | Store_Lookup | region_id | Many-to-One |
| Returns | store_id | Store_Lookup | store_id | Many-to-One |
| Transactions | customer_id | Customer_Lookup | customer_id | Many-to-One |
| Transactions | product_id | Product_Lookup | product_id | Many-to-One |
| Transactions | store_id | Store_Lookup | region_id | Many-to-One |
| Transactions | store_id | Store_Lookup | store_id | Many-to-One |
| Transactions | transaction_date | Calendar_Lookup | date | Many-to-One |

---
### Primary Key Structure
#### Primary Key Implementation
All dimension tables use clustered primary keys on natural business keys (date, customer_id, product_id, region_id, store_id). Fact tables use composite date + dimension keys.
    
**Primary Key Definitions:**

| Table Name | PK Constraint Name | PK Column | Clustered | Unique |
|------------|-------------------|-----------|-----------|--------|
| Calendar_Lookup | PK_Calendar_Lookup | date | Yes | Yes |
| Customer_Lookup | PK_Customer_Lookup | customer_id | Yes | Yes |
| Product_Lookup | PK_Product_Lookup | product_id | Yes | Yes |
| Region_Lookup | PK_Region_Lookup | region_id | Yes | Yes |
| Store_Lookup | PK_Store_Lookup | store_id | Yes | Yes |

---
### Star Schema Relationships
#### Fact-to-Dimension Mappings
Fact tables (Transactions, Returns) connect to dimension tables via foreign keys. Each fact record references 3-4 dimensions enabling multi-dimensional analysis (time, customer, product, location).
    
**Fact Table Dimensional Keys:**

| Fact Table | Foreign Keys | Dimension Tables Referenced |
|------------|--------------|----------------------------|
| Transactions | transaction_date, customer_id, product_id, store_id | Calendar_Lookup, Customer_Lookup, Product_Lookup, Store_Lookup |
| Returns | return_date, product_id, store_id | Calendar_Lookup, Product_Lookup, Store_Lookup |

---
### Table Definitions (DDL)

**Dimension Table: Calendar_Lookup**
```sql
CREATE TABLE dbo.Calendar_Lookup (
    -- Primary Key (Natural Key)
    date                DATE NOT NULL PRIMARY KEY CLUSTERED,
    
    -- Date Components
    Year                SMALLINT NOT NULL,
    Month               TINYINT NOT NULL CHECK (Month BETWEEN 1 AND 12),
    Month_Name          NVARCHAR(20) NOT NULL,
    Quarter             TINYINT NOT NULL CHECK (Quarter BETWEEN 1 AND 4),
    Day                 TINYINT NOT NULL CHECK (Day BETWEEN 1 AND 31),
    Day_Name            NVARCHAR(20) NOT NULL,
    
    -- Week Attributes
    Start_of_Week       DATE NOT NULL,
    
    -- Non-Clustered Indexes
    INDEX IX_Calendar_YearMonth NONCLUSTERED (Year, Month),
    INDEX IX_Calendar_Quarter NONCLUSTERED (Year, Quarter)
);
```

**Dimension Table: Customer_Lookup**
```sql
CREATE TABLE dbo.Customer_Lookup (
    -- Primary Key
    customer_id                 SMALLINT NOT NULL PRIMARY KEY CLUSTERED,
    
    -- Customer Identifiers
    customer_acct_num           BIGINT NOT NULL UNIQUE,
    
    -- Personal Information
    first_name                  NVARCHAR(50) NOT NULL,
    last_name                   NVARCHAR(50) NOT NULL,
    birthdate                   DATE NOT NULL,
    gender                      NVARCHAR(10) NOT NULL,
    marital_status              NVARCHAR(20) NOT NULL,
    
    -- Contact Information
    customer_address            NVARCHAR(100) NOT NULL,
    customer_city               NVARCHAR(50) NOT NULL,
    customer_state_province     NVARCHAR(50) NOT NULL,
    customer_postal_code        INT NOT NULL,
    customer_country            NVARCHAR(50) NOT NULL,
    
    -- Household Demographics
    yearly_income               NVARCHAR(20) NOT NULL,
    total_children              TINYINT NOT NULL DEFAULT 0,
    num_children_at_home        TINYINT NOT NULL DEFAULT 0,
    education                   NVARCHAR(50) NOT NULL,
    occupation                  NVARCHAR(50) NOT NULL,
    homeowner                   BIT NOT NULL DEFAULT 0,
    
    -- Account Information
    acct_open_date              DATE NOT NULL,
    member_card                 NVARCHAR(20) NOT NULL,
    
    -- Indexes
    INDEX IX_Customer_Country NONCLUSTERED (customer_country),
    INDEX IX_Customer_State NONCLUSTERED (customer_state_province)
);
```

**Dimension Table: Product_Lookup**
```sql
CREATE TABLE dbo.Product_Lookup (
    -- Primary Key
    product_id              SMALLINT NOT NULL PRIMARY KEY CLUSTERED,
    
    -- Product Identifiers
    product_sku             BIGINT NOT NULL UNIQUE,
    product_name            NVARCHAR(100) NOT NULL,
    product_brand           NVARCHAR(50) NOT NULL,
    
    -- Pricing
    product_retail_price    FLOAT NOT NULL CHECK (product_retail_price >= 0),
    product_cost            FLOAT NOT NULL CHECK (product_cost >= 0),
    
    -- Physical Attributes
    product_weight          FLOAT NOT NULL CHECK (product_weight >= 0),
    recyclable              TINYINT NULL,
    low_fat                 TINYINT NULL,
    
    -- Indexes
    INDEX IX_Product_Brand NONCLUSTERED (product_brand),
    INDEX IX_Product_Price NONCLUSTERED (product_retail_price)
);
```

**Dimension Table: Region_Lookup**
```sql
CREATE TABLE dbo.Region_Lookup (
    -- Primary Key
    region_id           TINYINT NOT NULL PRIMARY KEY CLUSTERED,
    
    -- Geographic Hierarchy
    sales_district      NVARCHAR(50) NOT NULL,
    sales_region        NVARCHAR(50) NOT NULL,
    
    -- Indexes
    INDEX IX_Region_District NONCLUSTERED (sales_district)
);
```

**Dimension Table: Store_Lookup**
```sql
CREATE TABLE dbo.Store_Lookup (
    -- Primary Key
    store_id                TINYINT NOT NULL PRIMARY KEY CLUSTERED,
    
    -- Foreign Key
    region_id               TINYINT NOT NULL,
    
    -- Store Attributes
    store_type              NVARCHAR(50) NOT NULL,
    store_name              NVARCHAR(100) NOT NULL,
    
    -- Location
    store_street_address    NVARCHAR(100) NOT NULL,
    store_city              NVARCHAR(50) NOT NULL,
    store_state             NVARCHAR(50) NOT NULL,
    store_country           NVARCHAR(50) NOT NULL,
    store_phone             NVARCHAR(20) NOT NULL,
    
    -- Operational Details
    first_opened_date       DATE NOT NULL,
    last_remodel_date       DATE NOT NULL,
    total_sqft              INT NOT NULL CHECK (total_sqft > 0),
    grocery_sqft            SMALLINT NOT NULL CHECK (grocery_sqft > 0),
    
    -- Foreign Key Constraint
    CONSTRAINT FK_Store_Region 
        FOREIGN KEY (region_id) REFERENCES Region_Lookup(region_id),
    
    -- Indexes
    INDEX IX_Store_Region NONCLUSTERED (region_id),
    INDEX IX_Store_Country NONCLUSTERED (store_country)
);
```

**Fact Table: Transactions**
```sql
CREATE TABLE dbo.Transactions (
    -- Composite Key (No Surrogate Key)
    transaction_date    DATE NOT NULL,
    product_id          SMALLINT NOT NULL,
    customer_id         SMALLINT NOT NULL,
    store_id            TINYINT NOT NULL,
    
    -- Additional Temporal Attribute
    stock_date          DATE NOT NULL,
    
    -- Measures
    quantity            TINYINT NOT NULL CHECK (quantity > 0),
    
    -- Foreign Key Constraints
    CONSTRAINT FK_Transactions_Date 
        FOREIGN KEY (transaction_date) REFERENCES Calendar_Lookup(date),
    CONSTRAINT FK_Transactions_Product 
        FOREIGN KEY (product_id) REFERENCES Product_Lookup(product_id),
    CONSTRAINT FK_Transactions_Customer 
        FOREIGN KEY (customer_id) REFERENCES Customer_Lookup(customer_id),
    CONSTRAINT FK_Transactions_Store 
        FOREIGN KEY (store_id) REFERENCES Store_Lookup(store_id),
    
    -- Non-Clustered Indexes for Query Performance
    INDEX IX_Transactions_Date NONCLUSTERED (transaction_date) INCLUDE (quantity),
    INDEX IX_Transactions_Customer NONCLUSTERED (customer_id),
    INDEX IX_Transactions_Product NONCLUSTERED (product_id) INCLUDE (quantity),
    INDEX IX_Transactions_Store NONCLUSTERED (store_id)
);
```

**Fact Table: Returns**
```sql
CREATE TABLE dbo.Returns (
    -- Composite Key
    return_date         DATE NOT NULL,
    product_id          SMALLINT NOT NULL,
    store_id            TINYINT NOT NULL,
    
    -- Measures
    quantity            TINYINT NOT NULL CHECK (quantity > 0),
    
    -- Foreign Key Constraints
    CONSTRAINT FK_Returns_Date 
        FOREIGN KEY (return_date) REFERENCES Calendar_Lookup(date),
    CONSTRAINT FK_Returns_Product 
        FOREIGN KEY (product_id) REFERENCES Product_Lookup(product_id),
    CONSTRAINT FK_Returns_Store 
        FOREIGN KEY (store_id) REFERENCES Store_Lookup(store_id),
    
    -- Non-Clustered Indexes
    INDEX IX_Returns_Date NONCLUSTERED (return_date),
    INDEX IX_Returns_Product NONCLUSTERED (product_id) INCLUDE (quantity),
    INDEX IX_Returns_Store NONCLUSTERED (store_id)
);
```

---

**Query Examples:**

**Query 1: Monthly Revenue by Product**
```sql
SELECT 
    c.Year,
    c.Month_Name,
    p.product_name,
    p.product_brand,
    SUM(t.quantity) AS total_quantity,
    COUNT(*) AS transaction_count,
    SUM(t.quantity * p.product_retail_price) AS total_revenue,
    SUM(t.quantity * p.product_cost) AS total_cost,
    SUM(t.quantity * (p.product_retail_price - p.product_cost)) AS gross_profit
FROM dbo.Transactions t
INNER JOIN dbo.Calendar_Lookup c ON t.transaction_date = c.date
INNER JOIN dbo.Product_Lookup p ON t.product_id = p.product_id
WHERE c.Year = 1998 AND c.Quarter = 1
GROUP BY c.Year, c.Month, c.Month_Name, p.product_name, p.product_brand
ORDER BY c.Month, total_revenue DESC;
```
**Excel Export**
<figure>
  <img src="/Career_Projects/assets/screenshots/bi-query.png" alt="Monthly Revenue by Product">
  <figcaption>Monthly Revenue by Product</figcaption>
</figure>

**Query 2: Customer Segmentation by Purchase Behavior**
```sql
SELECT 
    cu.customer_country,
    cu.customer_state_province,
    cu.yearly_income,
    COUNT(DISTINCT cu.customer_id) AS customer_count,
    SUM(t.quantity) AS total_units_purchased,
    COUNT(*) AS total_transactions,
    AVG(CAST(t.quantity AS FLOAT)) AS avg_basket_size
FROM dbo.Customer_Lookup cu
INNER JOIN dbo.Transactions t ON cu.customer_id = t.customer_id
GROUP BY cu.customer_country, cu.customer_state_province, cu.yearly_income
HAVING COUNT(*) > 100
ORDER BY customer_count DESC;
```
**Excel Export**
<figure>
  <img src="/Career_Projects/assets/screenshots/bi-query3.png" alt="Monthly Revenue by Product">
  <figcaption>Customer Segmentation by Purchase Behavior</figcaption>
</figure>

**Query 3: Store Performance Analysis**
```sql
SELECT 
    s.store_name,
    s.store_city,
    s.store_state,
    r.sales_region,
    COUNT(DISTINCT t.customer_id) AS unique_customers,
    SUM(t.quantity) AS total_units_sold,
    COUNT(*) AS total_transactions,
    SUM(t.quantity * p.product_retail_price) AS total_revenue,
    COUNT(ret.quantity) AS total_returns,
    CASE 
        WHEN COUNT(*) > 0 
        THEN CAST(COUNT(ret.quantity) AS FLOAT) / COUNT(*) * 100
        ELSE 0
    END AS return_rate_pct
FROM dbo.Store_Lookup s
INNER JOIN dbo.Region_Lookup r ON s.region_id = r.region_id
LEFT JOIN dbo.Transactions t ON s.store_id = t.store_id
LEFT JOIN dbo.Product_Lookup p ON t.product_id = p.product_id
LEFT JOIN dbo.Returns ret ON s.store_id = ret.store_id 
    AND t.product_id = ret.product_id
    AND t.transaction_date = ret.return_date
GROUP BY s.store_name, s.store_city, s.store_state, r.sales_region
ORDER BY total_revenue DESC;
```
**Excel Export**
<figure>
  <img src="/Career_Projects/assets/screenshots/bi-query2.png" alt="Store Performance Analysis">
  <figcaption>Store Performance Analysis</figcaption>
</figure>

## Analytics & Visualization

### Excel Pivot Analysis

**Metrics Implemented:**

- **Net Revenue:** `= [Total Transactions] - [Total Returns]`
- **Transaction %:** `= [Region Transactions] / [Total Transactions]`
- **Return Rate:** `= [Returns] / [Total Transactions]`

<div class="two-col-right">
  <div class="text-col">
    <h4>Regional Performance Analysis</h4>
    <p>
      Pivot table with slicer-based filtering (Region, Quarter) and timeline control for QTD analysis. Bar chart visualizes net revenue and transaction distribution across sales regions.
    </p>
    <p>
      <strong>Features:</strong> Dynamic slicers, timeline filters, conditional formatting, drill-through to transaction details.
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/bi-pivot-reg.png" alt="Regional Pivot Analysis">
      <figcaption>Regional Performance Pivot Table</figcaption>
    </figure>
  </div>
</div>

---

### DAX Time Intelligence

**Custom Measures:**
```dax
MTD Revenue = 
CALCULATE(
    SUM(Transactions[revenue]),
    DATESMTD('Calendar'[date])
)

QTD Revenue = 
CALCULATE(
    SUM(Transactions[revenue]),
    DATESQTD('Calendar'[date])
)

YTD Revenue = 
CALCULATE(
    SUM(Transactions[revenue]),
    DATESYTD('Calendar'[date])
)

Total Transactions = COUNTROWS(Transactions)

% of Total = 
DIVIDE(
    [Total Transactions],
    CALCULATE([Total Transactions], ALL(Transactions))
)
```

<div class="two-col-right">
  <div class="text-col">
    <h4>Time Intelligence Dashboard</h4>
    <p>
      Pivot table with Year/Quarter slicers showing MTD, QTD, YTD metrics alongside total transactions. Dynamic chart updates based on slicer selections.
    </p>
    <p>
      <strong>Use Case:</strong> Trend analysis, period-over-period comparison, seasonality detection.
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/diagrams/bi-pivot-time.png" alt="Time Intelligence Pivot">
      <figcaption>DAX Time Intelligence Measures</figcaption>
    </figure>
  </div>
</div>

---

### Power BI Dashboards

#### Main Dashboard

**KPIs:**

- Total Transactions: 269.7K
- Total Returns: 5.65K (2.1% return rate)
- Net Revenue: $1.19M
- Total Revenue: $1.2M

**Visualizations:**

1. **Transactions by Country** (Line Chart)
   - MTD/QTD/YTD trendlines for USA, Mexico, Canada
   - Drill-down to state/city level

2. **Transaction % by Region** (Bar Chart)
   - Horizontal bars ranked by volume
   - Top performer: North West (21.3%)

3. **Revenue by Quarter** (Pie Chart)
   - Q2/Q4 peak seasons ($326.4K each)
   - Q3 low season ($290.9K)

4. **Regional Detail Table**
   - City/State/Country hierarchy
   - Transaction percentage distribution

<figure>
  <img src="/Career_Projects/assets/diagrams/bi-powerbi-main.png" alt="Power BI Main Dashboard">
  <figcaption>Power BI Main Dashboard</figcaption>
</figure>

**Filters:** Year (1996-1998), Quarter (Q1-Q4), Country (Canada, Mexico, USA)

---

#### Product Dashboard

**Operational Metrics:**

- **Stores:** 24
- **Customers:** 1,648
- **Return Rate:** 1.0%
- **Products:** 1,560 SKUs
- **Manufacturers:** 111
- **Avg Retail Price:** $2.12

**Pricing Tier Analysis:**

| Tier | Avg Cost | Retail Price | Margin |
|------|----------|--------------|--------|
| Low | $0.52 | $1.30 | 150% |
| Medium | $1.02 | $2.55 | 150% |
| High | $1.46 | $3.56 | 144% |

**Regional Performance Table:**

- Columns: Manufacturer, Product Name, Qty Sold, Transactions, Total Revenue
- Sort: Descending by Total Revenue
- Drill-through: Product-level transaction details

<figure>
  <img src="/Career_Projects/assets/diagrams/bi-powerbi-product.png" alt="Power BI Product Dashboard">
  <figcaption>Power BI Product Analytics Dashboard</figcaption>
</figure>

**Regional Breakdown:**

- **North West:** 130K transactions, 400K units sold
- **Mexico Central:** 157K transactions, 50K units sold
- Additional regions: South West, Canada West, Mexico South

